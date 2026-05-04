/*
 * Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stddef.h>

int hw75_settings_save_one(const char *name, const void *value, size_t val_len);
int hw75_settings_delete(const char *name);
