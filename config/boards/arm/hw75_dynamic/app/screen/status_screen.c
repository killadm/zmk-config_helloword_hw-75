/*
 * Copyright (c) 2022-2023 XiNGRZ
 * SPDX-License-Identifier: MIT
 */

#include <zmk/display/status_screen.h>
#include <drivers/behavior/lvgl_key_press.h>

#include <logging/log.h>
LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

#include "layer_status.h"

lv_obj_t *zmk_display_status_screen()
{
	lv_group_t *group = lv_group_create();

	lv_obj_t *screen = lv_obj_create(NULL, NULL);
	layer_status_init(screen, group);

	lv_indev_t *indev = behavior_lvgl_get_indev();
	lv_indev_set_group(indev, group);

	return screen;
}
