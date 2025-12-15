/*
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#define DT_DRV_COMPAT zmk_behavior_otp

#include <zephyr/device.h>
#include <drivers/behavior.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>

#include <zmk/behavior.h>
#include <zmk/hid.h>
#include <zmk/event_manager.h>
#include <zmk/events/keycode_state_changed.h>

#include "../otp/totp.h"

LOG_MODULE_REGISTER(behavior_otp, CONFIG_ZMK_LOG_LEVEL);

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
			uint32_t keycode;
			if (code[i] == '0') {
				keycode = HID_USAGE_KEY_KEYBOARD_0_AND_RIGHT_PARENTHESIS;
			} else {
				keycode =
					HID_USAGE_KEY_KEYBOARD_1_AND_EXCLAMATION + (code[i] - '1');
			}

			// Simulate key press
			struct zmk_keycode_state_changed press_ev = {.usage_page = HID_USAGE_KEY,
								     .keycode = keycode,
								     .implicit_modifiers = 0,
								     .explicit_modifiers = 0,
								     .state = true,
								     .timestamp = k_uptime_get()};
			ZMK_EVENT_RAISE(new_zmk_keycode_state_changed(press_ev));

			k_sleep(K_MSEC(10));

			// Simulate key release
			struct zmk_keycode_state_changed release_ev = {.usage_page = HID_USAGE_KEY,
								       .keycode = keycode,
								       .implicit_modifiers = 0,
								       .explicit_modifiers = 0,
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

static int behavior_otp_init_wrap(const struct device *dev)
{
	return behavior_otp_init(dev);
}

DEVICE_DT_INST_DEFINE(0, behavior_otp_init_wrap, NULL, NULL, NULL, POST_KERNEL,
		      CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, &behavior_otp_driver_api);
