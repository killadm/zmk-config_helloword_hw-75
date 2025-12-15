/*
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
	       uint8_t *result);
