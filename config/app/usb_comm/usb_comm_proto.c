/*
 * Copyright (c) 2022-2023 XiNGRZ
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(usb_comm, CONFIG_HW75_USB_COMM_LOG_LEVEL);

#include <zephyr/usb/usb_device.h>
#include <stdlib.h>

#include <pb_encode.h>
#include <pb_decode.h>

#include <zmk/events/position_state_changed.h>
#include <zmk/event_manager.h>

#include "usb_comm_hid.h"
#include "usb_comm.pb.h"

#include "handler/handler.h"
#include "../otp/totp.h"

static struct k_sem usb_comm_sem;

static K_THREAD_STACK_DEFINE(usb_comm_thread_stack, CONFIG_HW75_USB_COMM_THREAD_STACK_SIZE);
static struct k_thread usb_comm_thread;

static uint32_t usb_rx_idx, usb_rx_len;
static uint8_t usb_rx_buf[CONFIG_HW75_USB_COMM_MAX_RX_MESSAGE_SIZE];
static uint8_t usb_tx_buf[CONFIG_HW75_USB_COMM_MAX_TX_MESSAGE_SIZE];

static uint8_t bytes_field[CONFIG_HW75_USB_COMM_MAX_BYTES_FIELD_SIZE];
static uint32_t bytes_field_len = 0;

uint32_t last_action = 0;
uint32_t last_payload_tag = 0;
uint32_t last_secret_len = 0;

struct bytes_arg {
	const uint8_t *buf;
	size_t len;
};

static bool write_bytes(pb_ostream_t *stream, const pb_field_t *field, void *const *arg)
{
	const struct bytes_arg *bytes = *arg;
	if (!pb_encode_tag_for_field(stream, field)) {
		return false;
	}
	return pb_encode_string(stream, bytes->buf, bytes->len);
}

#if CONFIG_HW75_USB_COMM_MAX_BYTES_FIELD_SIZE
static bool read_bytes_field(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
	ARG_UNUSED(field);
	ARG_UNUSED(arg);

	if (stream->bytes_left > sizeof(bytes_field)) {
		LOG_ERR("Buffer overflows decoding %d bytes", stream->bytes_left);
		return false;
	}

	uint32_t bytes_len = stream->bytes_left;

	if (!pb_read(stream, bytes_field, stream->bytes_left)) {
		LOG_ERR("Failed decoding bytes: %s", stream->errmsg);
		return false;
	}

	bytes_field_len = bytes_len;
	LOG_DBG("Decoded %d bytes", bytes_field_len);

	return true;
}
#endif

#if CONFIG_HW75_USB_COMM_MAX_BYTES_FIELD_SIZE
static bool h2d_callback(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
	if (field->tag == usb_comm_MessageH2D_eink_image_tag) {
		usb_comm_EinkImage *eink_image = field->pData;
		eink_image->bits.funcs.decode = read_bytes_field;
	} else if (field->tag == usb_comm_MessageH2D_otp_set_secret_tag) {
		usb_comm_OtpSetSecret *otp_set_secret = field->pData;
		otp_set_secret->secret.funcs.decode = read_bytes_field;
	}
	return true;
}
#endif

static void usb_comm_handle_message()
{
	LOG_DBG("message size %u", usb_rx_len);
	LOG_HEXDUMP_DBG(usb_rx_buf, MIN(usb_rx_len, 64), "message data");

	bytes_field_len = 0;

	pb_istream_t h2d_stream = pb_istream_from_buffer(usb_rx_buf, usb_rx_len);
	pb_ostream_t d2h_stream = pb_ostream_from_buffer(usb_tx_buf, sizeof(usb_tx_buf));

	usb_comm_MessageH2D h2d = usb_comm_MessageH2D_init_zero;
	usb_comm_MessageD2H d2h = usb_comm_MessageD2H_init_zero;

#if CONFIG_HW75_USB_COMM_MAX_BYTES_FIELD_SIZE
	h2d.cb_payload.funcs.decode = h2d_callback;
#endif

	if (!pb_decode_delimited(&h2d_stream, usb_comm_MessageH2D_fields, &h2d)) {
		LOG_ERR("Failed decoding h2d message: %s", h2d_stream.errmsg);
		return;
	}

	LOG_DBG("req action: %d", h2d.action);
	LOG_INF("Received Action: %d, Payload Tag: %d", h2d.action, h2d.which_payload);

	last_action = h2d.action;
	last_payload_tag = h2d.which_payload;

	d2h.action = h2d.action;
	d2h.which_payload = usb_comm_MessageD2H_nop_tag;

	STRUCT_SECTION_FOREACH(usb_comm_handler_config, config) {
		if (config->action == h2d.action) {
			if (config->handler(&h2d, &d2h, bytes_field, bytes_field_len)) {
				d2h.which_payload = config->response_payload;
			}
			break;
		}
	}

	size_t d2h_size;
	pb_get_encoded_size(&d2h_size, usb_comm_MessageD2H_fields, &d2h);
	if (d2h_size > sizeof(usb_tx_buf)) {
		LOG_ERR("The size of response for action %d is %d, exceeds max tx buf size %d",
			h2d.action, d2h_size, sizeof(usb_tx_buf));
	}

	if (!pb_encode_delimited(&d2h_stream, usb_comm_MessageD2H_fields, &d2h)) {
		LOG_ERR("Failed encoding d2h message: %s", d2h_stream.errmsg);
		return;
	}

	usb_comm_hid_send(usb_tx_buf, d2h_stream.bytes_written);
}

static void usb_comm_handle_packet(uint8_t *data, uint32_t len)
{
	if (usb_rx_idx + len > sizeof(usb_rx_buf)) {
		LOG_ERR("RX buffer overflows, index: %d, received: %d", usb_rx_idx, len);
		usb_rx_idx = 0;
		return;
	}

	if (data[0] + 1 > len) {
		LOG_ERR("Invalid packet header: %d, len: %d", data[0], len);
		return;
	}

	memcpy(usb_rx_buf + usb_rx_idx, data + 1, data[0]);
	usb_rx_idx += data[0];

	if (data[0] + 1 < len) {
		usb_rx_len = usb_rx_idx;
		usb_rx_idx = 0;
		k_sem_give(&usb_comm_sem);
	}
}

static void usb_comm_thread_entry(void *p1, void *p2, void *p3)
{
	usb_comm_hid_init(usb_comm_handle_packet);
	while (true) {
		k_sem_take(&usb_comm_sem, K_FOREVER);
		usb_comm_handle_message();
	}
}

static int usb_comm_init(const struct device *dev)
{
	ARG_UNUSED(dev);

	k_sem_init(&usb_comm_sem, 0, 1);

	k_thread_create(&usb_comm_thread, usb_comm_thread_stack,
			CONFIG_HW75_USB_COMM_THREAD_STACK_SIZE, usb_comm_thread_entry, NULL, NULL,
			NULL, K_PRIO_COOP(CONFIG_HW75_USB_COMM_THREAD_PRIORITY), 0, K_NO_WAIT);

	return 0;
}

static bool handle_simulate_input(const usb_comm_MessageH2D *h2d, usb_comm_MessageD2H *d2h,
				  const void *bytes, uint32_t bytes_len)
{
	ARG_UNUSED(bytes);
	ARG_UNUSED(bytes_len);

	if (h2d->which_payload != usb_comm_MessageH2D_simulate_input_tag) {
		LOG_ERR("SIMULATE_INPUT missing payload (tag %u)", h2d->which_payload);
		return false;
	}

	LOG_INF("Simulating input: pos %d, state %d", h2d->payload.simulate_input.position, h2d->payload.simulate_input.pressed);

	struct zmk_position_state_changed position_state_changed = {
		.position = h2d->payload.simulate_input.position,
		.state = h2d->payload.simulate_input.pressed,
		.timestamp = k_uptime_get(),
	};

	ZMK_EVENT_RAISE(new_zmk_position_state_changed(position_state_changed));

	d2h->payload.simulate_input.position = h2d->payload.simulate_input.position;
	d2h->payload.simulate_input.pressed = h2d->payload.simulate_input.pressed;

	return true;
}

static bool handle_otp_set_time(const usb_comm_MessageH2D *h2d, usb_comm_MessageD2H *d2h,
				const void *bytes, uint32_t bytes_len)
{
	LOG_INF("OTP Set Time: %llu", h2d->payload.otp_set_time.timestamp);
	totp_set_time(h2d->payload.otp_set_time.timestamp);
	d2h->payload.otp_set_time.timestamp = h2d->payload.otp_set_time.timestamp;
	return true;
}

static bool handle_otp_set_secret(const usb_comm_MessageH2D *h2d, usb_comm_MessageD2H *d2h,
				  const void *bytes, uint32_t bytes_len)
{
	if (h2d->which_payload != usb_comm_MessageH2D_otp_set_secret_tag) {
		LOG_ERR("OTP_SET_SECRET missing payload (tag %u)", h2d->which_payload);
		return false;
	}

	LOG_INF("OTP Set Secret: len %d", bytes_len);
	last_secret_len = bytes_len;
	if (bytes_len > 0) {
		totp_set_secret(bytes, bytes_len);
		static const uint8_t dummy = 0;
		static const struct bytes_arg empty = {.buf = &dummy, .len = 0};
		d2h->payload.otp_set_secret.secret.funcs.encode = write_bytes;
		d2h->payload.otp_set_secret.secret.arg = (void *)&empty;
		return true;
	}
	return false;
}

static bool handle_otp_get_state(const usb_comm_MessageH2D *h2d, usb_comm_MessageD2H *d2h,
				 const void *bytes, uint32_t bytes_len)
{
	char buf[16];
	if (totp_generate(buf, sizeof(buf)) == 0) {
		d2h->payload.otp_state.code = atoi(buf);
		LOG_INF("OTP Get State: %s -> %d", buf, d2h->payload.otp_state.code);
		return true;
	} else {
		LOG_ERR("OTP Generate failed");
	}
	return false;
}

USB_COMM_HANDLER_DEFINE(usb_comm_Action_SIMULATE_INPUT, usb_comm_MessageD2H_simulate_input_tag,
			handle_simulate_input);
USB_COMM_HANDLER_DEFINE(usb_comm_Action_OTP_SET_TIME, usb_comm_MessageD2H_otp_set_time_tag,
			handle_otp_set_time);
USB_COMM_HANDLER_DEFINE(usb_comm_Action_OTP_SET_SECRET, usb_comm_MessageD2H_otp_set_secret_tag,
			handle_otp_set_secret);
USB_COMM_HANDLER_DEFINE(usb_comm_Action_OTP_GET_STATE, usb_comm_MessageD2H_otp_state_tag,
			handle_otp_get_state);

SYS_INIT(usb_comm_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
