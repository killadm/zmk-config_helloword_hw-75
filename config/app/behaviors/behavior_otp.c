/*
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#define DT_DRV_COMPAT zmk_behavior_otp

#include <zephyr/device.h>
#include <drivers/behavior.h>
#include <zephyr/logging/log.h>

#include <zmk/behavior.h>
#include <zmk/hid.h>
#include <dt-bindings/zmk/keys.h>
#include <zmk/event_manager.h>
#include <zmk/events/keycode_state_changed.h>

#include "../otp/totp.h"

LOG_MODULE_REGISTER(behavior_otp, CONFIG_ZMK_LOG_LEVEL);

struct behavior_otp_config {
};

struct behavior_otp_data {
};

static int behavior_otp_init(const struct device *dev)
{
	return 0;
}

static int on_keymap_binding_pressed(struct zmk_behavior_binding *binding,
				     struct zmk_behavior_binding_event event)
{
	char code[7];
	totp_generate(code, sizeof(code));

	LOG_INF("Typing OTP: %s", code);

	for (int i = 0; i < 6; i++) {
		if (code[i] >= '0' && code[i] <= '9') {
			uint8_t usage = ZMK_HID_USAGE(
				HID_USAGE_KEY,
				HID_USAGE_KEY_KEYBOARD_0_AND_RIGHT_PARENTHESIS + (code[i] - '0'));
			if (code[i] == '0') {
				usage = ZMK_HID_USAGE(
					HID_USAGE_KEY,
					HID_USAGE_KEY_KEYBOARD_0_AND_RIGHT_PARENTHESIS);
			} else {
				usage = ZMK_HID_USAGE(HID_USAGE_KEY,
						      HID_USAGE_KEY_KEYBOARD_1_AND_EXCLAMATION +
							      (code[i] - '1'));
			}

			// Simulate key press and release
			struct zmk_keycode_state_changed press_ev = {.usage_page = HID_USAGE_KEY,
								     .keycode = usage,
								     .implicit_modifiers = 0,
								     .state = true,
								     .timestamp = k_uptime_get()};
			ZMK_EVENT_RAISE(new_zmk_keycode_state_changed(press_ev));

			k_sleep(K_MSEC(10));

			struct zmk_keycode_state_changed release_ev = {.usage_page = HID_USAGE_KEY,
								       .keycode = usage,
								       .implicit_modifiers = 0,
								       .state = false,
								       .timestamp = k_uptime_get()};
			ZMK_EVENT_RAISE(new_zmk_keycode_state_changed(release_ev));

			k_sleep(K_MSEC(10));
		}
	}

	return ZMK_BEHAVIOR_OPAQUE;
}

static int on_keymap_binding_released(struct zmk_behavior_binding *binding,
				      struct zmk_behavior_binding_event event)
{
	return ZMK_BEHAVIOR_OPAQUE;
}

static const struct behavior_driver_api behavior_otp_driver_api = {
	.binding_pressed = on_keymap_binding_pressed,
	.binding_released = on_keymap_binding_released,
};

BEHAVIOR_DT_INST_DEFINE(0, behavior_otp_init, NULL, &behavior_otp_data, &behavior_otp_config,
			POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, &behavior_otp_driver_api);
