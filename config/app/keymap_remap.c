/*
 * Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/util.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

#include <zmk/behavior.h>
#include <zmk/keymap.h>
#include <zmk/matrix.h>
#include <dt-bindings/zmk/hid_usage_pages.h>

#include <app/keymap_remap.h>
#include <app/settings_work.h>

#define KEYMAP_REMAP_TOTAL_ENTRIES (ZMK_KEYMAP_LAYERS_LEN * ZMK_KEYMAP_LEN)
#define KEYMAP_REMAP_CEIL_DIV(n, d) (((n) + (d) - 1) / (d))
#define KEYMAP_REMAP_PAGE_COUNT                                                                 \
	KEYMAP_REMAP_CEIL_DIV(KEYMAP_REMAP_TOTAL_ENTRIES, HW75_KEYMAP_REMAP_PAGE_SIZE)
#define KEYMAP_REMAP_PAGE_STORAGE_SIZE                                                           \
	(2 + (HW75_KEYMAP_REMAP_PAGE_SIZE * sizeof(struct hw75_keymap_remap_entry)))

BUILD_ASSERT(KEYMAP_REMAP_PAGE_COUNT <= 32, "HW75 keymap remap dirty mask is uint32_t");
BUILD_ASSERT(sizeof(struct hw75_keymap_remap_entry) == 6, "Unexpected packed entry size");

static const char LABEL_KP[] = "KEY_PRESS";
static const char LABEL_NONE[] = "NONE";
static const char LABEL_TRANS[] = "TRANS";
static const char LABEL_MO[] = "MO";
static const char LABEL_TO[] = "TO_LAYER";
static const char LABEL_TOG[] = "TOGGLE_LAYER";
static const char LABEL_SL[] = "STICKY_LAYER";

static uint32_t dirty_pages;

static char hex_digit(uint8_t value)
{
	return value < 10 ? ('0' + value) : ('a' + value - 10);
}

static int hex_value(char value)
{
	if (value >= '0' && value <= '9') {
		return value - '0';
	}
	if (value >= 'a' && value <= 'f') {
		return value - 'a' + 10;
	}
	if (value >= 'A' && value <= 'F') {
		return value - 'A' + 10;
	}
	return -EINVAL;
}

static void page_path(uint8_t page, char *path)
{
	memcpy(path, "app/keymap/p00", sizeof("app/keymap/p00"));
	path[12] = hex_digit(page >> 4);
	path[13] = hex_digit(page & 0x0F);
}

static int page_from_name(const char *name)
{
	if (!name || name[0] != 'p' || name[1] == '\0' || name[2] == '\0' || name[3] != '\0') {
		return -EINVAL;
	}

	int hi = hex_value(name[1]);
	int lo = hex_value(name[2]);
	if (hi < 0 || lo < 0) {
		return -EINVAL;
	}

	int page = (hi << 4) | lo;
	return page < KEYMAP_REMAP_PAGE_COUNT ? page : -EINVAL;
}

static bool bindings_equal(const struct zmk_behavior_binding *a,
			   const struct zmk_behavior_binding *b)
{
	if (a->param1 != b->param1 || a->param2 != b->param2) {
		return false;
	}
	if (a->behavior_dev == b->behavior_dev) {
		return true;
	}
	if (!a->behavior_dev || !b->behavior_dev) {
		return false;
	}
	return strcmp(a->behavior_dev, b->behavior_dev) == 0;
}

static bool label_is(const struct zmk_behavior_binding *binding, const char *label)
{
	return binding->behavior_dev && strcmp(binding->behavior_dev, label) == 0;
}

static bool valid_kp_param(uint32_t param)
{
	uint32_t page = ZMK_HID_USAGE_PAGE(param);

	return page == HID_USAGE_KEY || page == HID_USAGE_CONSUMER;
}

static int entry_to_binding(const struct hw75_keymap_remap_entry *entry,
			    struct zmk_behavior_binding *binding)
{
	*binding = (struct zmk_behavior_binding){
		.param1 = entry->param,
		.param2 = 0,
	};

	switch (entry->behavior) {
	case HW75_KEYMAP_BEHAVIOR_KP:
		if (!valid_kp_param(entry->param)) {
			return -EINVAL;
		}
		binding->behavior_dev = (char *)LABEL_KP;
		break;
	case HW75_KEYMAP_BEHAVIOR_NONE:
		binding->behavior_dev = (char *)LABEL_NONE;
		binding->param1 = 0;
		break;
	case HW75_KEYMAP_BEHAVIOR_TRANS:
		binding->behavior_dev = (char *)LABEL_TRANS;
		binding->param1 = 0;
		break;
	case HW75_KEYMAP_BEHAVIOR_MO:
		binding->behavior_dev = (char *)LABEL_MO;
		break;
	case HW75_KEYMAP_BEHAVIOR_TO:
		binding->behavior_dev = (char *)LABEL_TO;
		break;
	case HW75_KEYMAP_BEHAVIOR_TOG:
		binding->behavior_dev = (char *)LABEL_TOG;
		break;
	case HW75_KEYMAP_BEHAVIOR_SL:
		binding->behavior_dev = (char *)LABEL_SL;
		break;
	default:
		return -EINVAL;
	}

	if (entry->behavior >= HW75_KEYMAP_BEHAVIOR_MO &&
	    entry->behavior <= HW75_KEYMAP_BEHAVIOR_SL &&
	    entry->param >= zmk_keymap_layer_count()) {
		return -EINVAL;
	}

	return 0;
}

static int binding_to_entry(uint8_t page_offset, const struct zmk_behavior_binding *binding,
			    struct hw75_keymap_remap_entry *entry)
{
	*entry = (struct hw75_keymap_remap_entry){
		.position = page_offset,
		.param = binding->param1,
	};

	if (label_is(binding, LABEL_KP)) {
		entry->behavior = HW75_KEYMAP_BEHAVIOR_KP;
	} else if (label_is(binding, LABEL_NONE)) {
		entry->behavior = HW75_KEYMAP_BEHAVIOR_NONE;
		entry->param = 0;
	} else if (label_is(binding, LABEL_TRANS)) {
		entry->behavior = HW75_KEYMAP_BEHAVIOR_TRANS;
		entry->param = 0;
	} else if (label_is(binding, LABEL_MO)) {
		entry->behavior = HW75_KEYMAP_BEHAVIOR_MO;
	} else if (label_is(binding, LABEL_TO)) {
		entry->behavior = HW75_KEYMAP_BEHAVIOR_TO;
	} else if (label_is(binding, LABEL_TOG)) {
		entry->behavior = HW75_KEYMAP_BEHAVIOR_TOG;
	} else if (label_is(binding, LABEL_SL)) {
		entry->behavior = HW75_KEYMAP_BEHAVIOR_SL;
	} else {
		return -ENOTSUP;
	}

	return 0;
}

static bool page_offset_to_key(uint8_t page, uint8_t page_offset, uint8_t *layer,
			       uint32_t *position)
{
	uint32_t flat = (page * HW75_KEYMAP_REMAP_PAGE_SIZE) + page_offset;
	if (flat >= KEYMAP_REMAP_TOTAL_ENTRIES) {
		return false;
	}

	*layer = flat / ZMK_KEYMAP_LEN;
	*position = flat % ZMK_KEYMAP_LEN;
	return true;
}

uint8_t hw75_keymap_remap_layer_count(void)
{
	return zmk_keymap_layer_count();
}

uint32_t hw75_keymap_remap_position_count(void)
{
	return zmk_keymap_position_count();
}

uint8_t hw75_keymap_remap_page_size(void)
{
	return HW75_KEYMAP_REMAP_PAGE_SIZE;
}

uint8_t hw75_keymap_remap_page_count(void)
{
	return KEYMAP_REMAP_PAGE_COUNT;
}

uint32_t hw75_keymap_remap_dirty_pages(void)
{
	return dirty_pages;
}

int hw75_keymap_remap_collect_page(uint8_t page, struct hw75_keymap_remap_entry *entries,
				   uint8_t *count)
{
	if (!entries || !count || page >= KEYMAP_REMAP_PAGE_COUNT) {
		return -EINVAL;
	}

	*count = 0;
	for (uint8_t offset = 0; offset < HW75_KEYMAP_REMAP_PAGE_SIZE; offset++) {
		uint8_t layer;
		uint32_t position;
		if (!page_offset_to_key(page, offset, &layer, &position)) {
			break;
		}

		struct zmk_behavior_binding current;
		struct zmk_behavior_binding defaults;
		int ret = zmk_keymap_get_binding(layer, position, &current);
		if (ret) {
			return ret;
		}
		ret = zmk_keymap_get_default_binding(layer, position, &defaults);
		if (ret) {
			return ret;
		}
		if (bindings_equal(&current, &defaults)) {
			continue;
		}

		ret = binding_to_entry(offset, &current, &entries[*count]);
		if (ret) {
			return ret;
		}
		(*count)++;
	}

	return 0;
}

static int save_page_entries(uint8_t page, const struct hw75_keymap_remap_entry *entries,
			     uint8_t count)
{
	if (page >= KEYMAP_REMAP_PAGE_COUNT || count > HW75_KEYMAP_REMAP_PAGE_SIZE) {
		return -EINVAL;
	}

	char path[sizeof("app/keymap/p00")];
	page_path(page, path);

	if (count == 0) {
		int ret = hw75_settings_delete(path);
		if (ret == 0 || ret == -ENOENT) {
			dirty_pages &= ~BIT(page);
			return 0;
		}
		return ret;
	}

	uint8_t buffer[KEYMAP_REMAP_PAGE_STORAGE_SIZE];
	buffer[0] = HW75_KEYMAP_REMAP_PROFILE;
	buffer[1] = count;
	memcpy(&buffer[2], entries, count * sizeof(entries[0]));

	int ret = hw75_settings_save_one(path, buffer, 2 + count * sizeof(entries[0]));
	if (ret == 0) {
		dirty_pages |= BIT(page);
	}
	return ret;
}

static int validate_page_entries(uint8_t page, const struct hw75_keymap_remap_entry *entries,
				 uint8_t count,
				 struct zmk_keymap_binding_update *updates,
				 uint8_t *update_count)
{
	if (page >= KEYMAP_REMAP_PAGE_COUNT || count > HW75_KEYMAP_REMAP_PAGE_SIZE ||
	    (!entries && count > 0)) {
		return -EINVAL;
	}

	uint16_t seen_offsets = 0;

	for (uint8_t offset = 0; offset < HW75_KEYMAP_REMAP_PAGE_SIZE; offset++) {
		uint8_t layer;
		uint32_t position;
		if (!page_offset_to_key(page, offset, &layer, &position)) {
			break;
		}
		updates[offset] = (struct zmk_keymap_binding_update){
			.layer = layer,
			.position = position,
		};
		int ret = zmk_keymap_get_default_binding(layer, position, &updates[offset].binding);
		if (ret) {
			return ret;
		}
	}

	*update_count = 0;
	for (uint8_t offset = 0; offset < HW75_KEYMAP_REMAP_PAGE_SIZE; offset++) {
		uint8_t layer;
		uint32_t position;
		if (!page_offset_to_key(page, offset, &layer, &position)) {
			break;
		}
		ARG_UNUSED(layer);
		ARG_UNUSED(position);
		(*update_count)++;
	}

	for (uint8_t i = 0; i < count; i++) {
		if (entries[i].position >= HW75_KEYMAP_REMAP_PAGE_SIZE) {
			return -EINVAL;
		}
		if (seen_offsets & BIT(entries[i].position)) {
			return -EINVAL;
		}
		seen_offsets |= BIT(entries[i].position);

		uint8_t layer;
		uint32_t position;
		if (!page_offset_to_key(page, entries[i].position, &layer, &position)) {
			return -EINVAL;
		}

		if (entries[i].behavior != HW75_KEYMAP_BEHAVIOR_DEFAULT) {
			int ret = entry_to_binding(&entries[i],
						   &updates[entries[i].position].binding);
			if (ret) {
				return ret;
			}
		}
	}

	return 0;
}

static int apply_page_entries(uint8_t page, const struct hw75_keymap_remap_entry *entries,
			      uint8_t count)
{
	struct zmk_keymap_binding_update updates[HW75_KEYMAP_REMAP_PAGE_SIZE];
	uint8_t update_count = 0;
	int ret = validate_page_entries(page, entries, count, updates, &update_count);
	if (ret) {
		return ret;
	}

	return zmk_keymap_update_bindings(updates, update_count);
}

int hw75_keymap_remap_set_page(uint8_t page, const struct hw75_keymap_remap_entry *entries,
			       uint8_t count)
{
	struct zmk_keymap_binding_update updates[HW75_KEYMAP_REMAP_PAGE_SIZE];
	uint8_t update_count = 0;
	int ret = validate_page_entries(page, entries, count, updates, &update_count);
	if (ret) {
		return ret;
	}

	ret = zmk_keymap_update_bindings(updates, update_count);
	if (ret) {
		return ret;
	}

	return save_page_entries(page, entries, count);
}

int hw75_keymap_remap_reset_key(uint8_t layer, uint32_t position)
{
	if (layer >= zmk_keymap_layer_count() || position >= zmk_keymap_position_count()) {
		return -EINVAL;
	}

	uint32_t flat = (layer * zmk_keymap_position_count()) + position;
	uint8_t page = flat / HW75_KEYMAP_REMAP_PAGE_SIZE;
	uint8_t page_offset = flat % HW75_KEYMAP_REMAP_PAGE_SIZE;
	struct hw75_keymap_remap_entry entries[HW75_KEYMAP_REMAP_PAGE_SIZE];
	uint8_t count = 0;
	int ret = hw75_keymap_remap_collect_page(page, entries, &count);
	if (ret) {
		return ret;
	}

	uint8_t write = 0;
	for (uint8_t read = 0; read < count; read++) {
		if (entries[read].position == page_offset) {
			continue;
		}
		entries[write++] = entries[read];
	}

	return hw75_keymap_remap_set_page(page, entries, write);
}

int hw75_keymap_remap_reset_layer(uint8_t layer)
{
	if (layer >= zmk_keymap_layer_count()) {
		return -EINVAL;
	}
	int ret = 0;
	uint32_t positions = zmk_keymap_position_count();
	uint8_t first_page = (layer * positions) / HW75_KEYMAP_REMAP_PAGE_SIZE;
	uint8_t last_page = (((layer + 1) * positions) - 1) / HW75_KEYMAP_REMAP_PAGE_SIZE;

	for (uint8_t page = first_page; page <= last_page; page++) {
		struct hw75_keymap_remap_entry entries[HW75_KEYMAP_REMAP_PAGE_SIZE];
		uint8_t count = 0;
		ret = hw75_keymap_remap_collect_page(page, entries, &count);
		if (ret) {
			return ret;
		}

		uint8_t write = 0;
		for (uint8_t read = 0; read < count; read++) {
			uint8_t entry_layer;
			uint32_t entry_position;
			if (!page_offset_to_key(page, entries[read].position, &entry_layer,
						&entry_position)) {
				return -EINVAL;
			}
			if (entry_layer == layer) {
				continue;
			}
			entries[write++] = entries[read];
		}

		ret = hw75_keymap_remap_set_page(page, entries, write);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

int hw75_keymap_remap_reset_all(void)
{
	int ret = 0;
	for (uint8_t page = 0; page < KEYMAP_REMAP_PAGE_COUNT; page++) {
		ret = hw75_keymap_remap_set_page(page, NULL, 0);
		if (ret) {
			return ret;
		}
	}

	dirty_pages = 0;
	return 0;
}

static int load_page(uint8_t page, const uint8_t *buffer, size_t len)
{
	if (len < 2 || len > KEYMAP_REMAP_PAGE_STORAGE_SIZE ||
	    buffer[0] != HW75_KEYMAP_REMAP_PROFILE) {
		return -EINVAL;
	}

	uint8_t count = buffer[1];
	if (count > HW75_KEYMAP_REMAP_PAGE_SIZE ||
	    len != 2 + count * sizeof(struct hw75_keymap_remap_entry)) {
		return -EINVAL;
	}

	const struct hw75_keymap_remap_entry *entries =
		(const struct hw75_keymap_remap_entry *)&buffer[2];
	uint16_t seen_offsets = 0;

	for (uint8_t i = 0; i < count; i++) {
		if (entries[i].position >= HW75_KEYMAP_REMAP_PAGE_SIZE ||
		    (seen_offsets & BIT(entries[i].position))) {
			return -EINVAL;
		}
		seen_offsets |= BIT(entries[i].position);

		uint8_t layer;
		uint32_t position;
		if (!page_offset_to_key(page, entries[i].position, &layer, &position)) {
			return -EINVAL;
		}

		struct zmk_behavior_binding binding;
		int ret = entry_to_binding(&entries[i], &binding);
		if (ret) {
			return ret;
		}
	}

	int ret = apply_page_entries(page, entries, count);
	if (ret) {
		return ret;
	}

	dirty_pages |= BIT(page);
	return 0;
}

static int keymap_remap_settings_load_cb(const char *name, size_t len, settings_read_cb read_cb,
					 void *cb_arg, void *param)
{
	ARG_UNUSED(param);

	int page = page_from_name(name);
	if (page < 0) {
		return -ENOENT;
	}

	uint8_t buffer[KEYMAP_REMAP_PAGE_STORAGE_SIZE];
	int ret = read_cb(cb_arg, buffer, len);
	if (ret < 0) {
		return ret;
	}
	if ((size_t)ret != len) {
		return -EINVAL;
	}

	ret = load_page(page, buffer, len);
	if (ret) {
		LOG_WRN("Ignoring keymap remap page %s: %d", name, ret);
		return 0;
	}

	return 0;
}

static int keymap_remap_init(const struct device *dev)
{
	ARG_UNUSED(dev);

	int ret = settings_subsys_init();
	if (ret) {
		LOG_ERR("Failed to initialize settings subsys: %d", ret);
	}

	ret = settings_load_subtree_direct("app/keymap", keymap_remap_settings_load_cb, NULL);
	if (ret) {
		LOG_ERR("Failed to load keymap remap settings: %d", ret);
	}

	return 0;
}

SYS_INIT(keymap_remap_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
