/*
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

void totp_set_secret(const uint8_t *secret, size_t len);
void totp_set_time(uint64_t timestamp);
int totp_generate(char *buf, size_t len);
