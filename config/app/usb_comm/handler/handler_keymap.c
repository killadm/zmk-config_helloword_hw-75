/*
 * Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <string.h>

#include <pb_encode.h>

#include <app/keymap_remap.h>

#include "handler.h"
#include "usb_comm.pb.h"

static uint8_t page_entries_bytes[HW75_KEYMAP_REMAP_PAGE_SIZE *
				  sizeof(struct hw75_keymap_remap_entry)];
static uint32_t page_entries_bytes_len;

static usb_comm_KeymapStatus_Status status_from_ret(int ret)
{
	if (ret == 0) {
		return usb_comm_KeymapStatus_Status_OK;
	}
	if (ret == -EBUSY) {
		return usb_comm_KeymapStatus_Status_BUSY;
	}
	if (ret == -EINVAL || ret == -ENOTSUP) {
		return usb_comm_KeymapStatus_Status_INVALID;
	}
	return usb_comm_KeymapStatus_Status_ERROR;
}

static bool write_page_entries(pb_ostream_t *stream, const pb_field_t *field, void *const *arg)
{
	ARG_UNUSED(arg);

	if (!pb_encode_tag_for_field(stream, field)) {
		return false;
	}
	return pb_encode_string(stream, page_entries_bytes, page_entries_bytes_len);
}

static void fill_status(usb_comm_KeymapStatus *status, int ret)
{
	status->status = status_from_ret(ret);
	status->dirty_pages = hw75_keymap_remap_dirty_pages();
	status->has_dirty_pages = true;
}

static bool handle_keymap_info(const usb_comm_MessageH2D *h2d, usb_comm_MessageD2H *d2h,
			       const void *bytes, uint32_t bytes_len)
{
	ARG_UNUSED(h2d);
	ARG_UNUSED(bytes);
	ARG_UNUSED(bytes_len);

	usb_comm_KeymapInfo *res = &d2h->payload.keymap_info;
	res->layers = hw75_keymap_remap_layer_count();
	res->positions = hw75_keymap_remap_position_count();
	res->page_size = hw75_keymap_remap_page_size();
	res->page_count = hw75_keymap_remap_page_count();
	res->dirty_pages = hw75_keymap_remap_dirty_pages();
	res->profile = HW75_KEYMAP_REMAP_PROFILE;

	return true;
}

USB_COMM_HANDLER_DEFINE(usb_comm_Action_KEYMAP_INFO, usb_comm_MessageD2H_keymap_info_tag,
			handle_keymap_info);

static bool handle_keymap_get_page(const usb_comm_MessageH2D *h2d, usb_comm_MessageD2H *d2h,
				   const void *bytes, uint32_t bytes_len)
{
	ARG_UNUSED(bytes);
	ARG_UNUSED(bytes_len);

	const usb_comm_KeymapPage *req = &h2d->payload.keymap_page;
	usb_comm_KeymapPage *res = &d2h->payload.keymap_page;

	struct hw75_keymap_remap_entry entries[HW75_KEYMAP_REMAP_PAGE_SIZE];
	uint8_t count = 0;
	int ret = hw75_keymap_remap_collect_page(req->page, entries, &count);
	if (ret) {
		count = 0;
	}

	res->page = req->page;
	page_entries_bytes_len = count * sizeof(entries[0]);
	if (page_entries_bytes_len > 0) {
		memcpy(page_entries_bytes, entries, page_entries_bytes_len);
		res->entries.funcs.encode = write_page_entries;
	}

	return true;
}

USB_COMM_HANDLER_DEFINE(usb_comm_Action_KEYMAP_GET_PAGE, usb_comm_MessageD2H_keymap_page_tag,
			handle_keymap_get_page);

static bool handle_keymap_set_page(const usb_comm_MessageH2D *h2d, usb_comm_MessageD2H *d2h,
				   const void *bytes, uint32_t bytes_len)
{
	const usb_comm_KeymapPage *req = &h2d->payload.keymap_page;
	usb_comm_KeymapStatus *res = &d2h->payload.keymap_status;

	int ret = 0;
	if (bytes_len % sizeof(struct hw75_keymap_remap_entry) != 0 ||
	    bytes_len > sizeof(page_entries_bytes)) {
		ret = -EINVAL;
	} else {
		ret = hw75_keymap_remap_set_page(
			req->page, (const struct hw75_keymap_remap_entry *)bytes,
			bytes_len / sizeof(struct hw75_keymap_remap_entry));
	}

	fill_status(res, ret);
	res->page = req->page;
	res->has_page = true;

	return true;
}

USB_COMM_HANDLER_DEFINE(usb_comm_Action_KEYMAP_SET_PAGE, usb_comm_MessageD2H_keymap_status_tag,
			handle_keymap_set_page);

static bool handle_keymap_reset(const usb_comm_MessageH2D *h2d, usb_comm_MessageD2H *d2h,
				const void *bytes, uint32_t bytes_len)
{
	ARG_UNUSED(bytes);
	ARG_UNUSED(bytes_len);

	const usb_comm_KeymapReset *req = &h2d->payload.keymap_reset;
	usb_comm_KeymapStatus *res = &d2h->payload.keymap_status;

	int ret;
	switch (req->scope) {
	case usb_comm_KeymapReset_Scope_ALL:
		ret = hw75_keymap_remap_reset_all();
		break;
	case usb_comm_KeymapReset_Scope_LAYER:
		ret = req->has_layer ? hw75_keymap_remap_reset_layer(req->layer) : -EINVAL;
		break;
	case usb_comm_KeymapReset_Scope_KEY:
		ret = req->has_layer && req->has_position ?
			      hw75_keymap_remap_reset_key(req->layer, req->position) :
			      -EINVAL;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	fill_status(res, ret);

	return true;
}

USB_COMM_HANDLER_DEFINE(usb_comm_Action_KEYMAP_RESET, usb_comm_MessageD2H_keymap_status_tag,
			handle_keymap_reset);
