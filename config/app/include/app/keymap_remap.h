/*
 * Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>

#include <zephyr/sys/util.h>

#define HW75_KEYMAP_REMAP_PROFILE   1
#define HW75_KEYMAP_REMAP_PAGE_SIZE 9

enum hw75_keymap_remap_behavior {
	HW75_KEYMAP_BEHAVIOR_DEFAULT = 0,
	HW75_KEYMAP_BEHAVIOR_KP = 1,
	HW75_KEYMAP_BEHAVIOR_NONE = 2,
	HW75_KEYMAP_BEHAVIOR_TRANS = 3,
	HW75_KEYMAP_BEHAVIOR_MO = 4,
	HW75_KEYMAP_BEHAVIOR_TO = 5,
	HW75_KEYMAP_BEHAVIOR_TOG = 6,
	HW75_KEYMAP_BEHAVIOR_SL = 7,
};

struct hw75_keymap_remap_entry {
	uint8_t position;
	uint8_t behavior;
	uint32_t param;
} __packed;

uint8_t hw75_keymap_remap_layer_count(void);
uint32_t hw75_keymap_remap_position_count(void);
uint8_t hw75_keymap_remap_page_size(void);
uint8_t hw75_keymap_remap_page_count(void);
uint32_t hw75_keymap_remap_dirty_pages(void);

int hw75_keymap_remap_collect_page(uint8_t page, struct hw75_keymap_remap_entry *entries,
				   uint8_t *count);
int hw75_keymap_remap_set_page(uint8_t page, const struct hw75_keymap_remap_entry *entries,
			       uint8_t count);
int hw75_keymap_remap_reset_all(void);
int hw75_keymap_remap_reset_layer(uint8_t layer);
int hw75_keymap_remap_reset_key(uint8_t layer, uint32_t position);
