/*
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include "totp.h"
#include "hmac_sha1.h"

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/settings/settings.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

LOG_MODULE_REGISTER(otp, CONFIG_ZMK_LOG_LEVEL);

#define OTP_SECRET_MAX_LEN 64
#define OTP_TIME_STEP      30
#define OTP_MIN_TIMESTAMP  1797033600 // 2026-12-12 00:00:00 UTC

static uint8_t secret[OTP_SECRET_MAX_LEN];
static size_t secret_len = 0;
static uint64_t time_offset = 0;
static uint64_t last_sync_uptime = 0;

static uint64_t get_current_time(void)
{
	if (time_offset == 0) {
		return 0;
	}
	return time_offset + (k_uptime_get() - last_sync_uptime) / 1000;
}

void totp_set_secret(const uint8_t *sec, size_t len)
{
	secret_len = len > OTP_SECRET_MAX_LEN ? OTP_SECRET_MAX_LEN : len;
	memcpy(secret, sec, secret_len);

#ifdef CONFIG_SETTINGS
	settings_save_one("app/otp/secret", secret, secret_len);
#endif
}

void totp_set_time(uint64_t timestamp)
{
	time_offset = timestamp;
	last_sync_uptime = k_uptime_get();
	LOG_INF("Time synced: %" PRIu64, timestamp);
}

static uint32_t truncate_hmac(uint8_t *hmac_result)
{
	int offset = hmac_result[19] & 0xf;
	return ((hmac_result[offset] & 0x7f) << 24) | ((hmac_result[offset + 1] & 0xff) << 16) |
	       ((hmac_result[offset + 2] & 0xff) << 8) | (hmac_result[offset + 3] & 0xff);
}

int totp_generate(char *buf, size_t len)
{
	uint64_t now = get_current_time();

	if (now < OTP_MIN_TIMESTAMP) {
		LOG_WRN("Time not synced or too old (%" PRIu64 " < %" PRIu64 "), returning 000000",
			now, OTP_MIN_TIMESTAMP);
		snprintf(buf, len, "000000");
		return 0;
	}

	if (secret_len == 0) {
		LOG_WRN("No secret set");
		snprintf(buf, len, "000000");
		return -1;
	}

	uint64_t steps = now / OTP_TIME_STEP;
	uint8_t challenge[8];
	for (int i = 7; i >= 0; i--) {
		challenge[i] = steps & 0xff;
		steps >>= 8;
	}

	uint8_t hmac_result[20];
	hmac_sha1(secret, secret_len, challenge, 8, hmac_result);

	uint32_t truncated = truncate_hmac(hmac_result);
	uint32_t otp = truncated % 1000000;

	snprintf(buf, len, "%06u", otp);
	return 0;
}

#ifdef CONFIG_SETTINGS
static int otp_settings_load_cb(const char *name, size_t len, settings_read_cb read_cb,
				void *cb_arg, void *param)
{
	const char *next;
	int ret;

	if (settings_name_steq(name, "secret", &next) && !next) {
		if (len > sizeof(secret)) {
			return -EINVAL;
		}

		ret = read_cb(cb_arg, secret, len);
		if (ret >= 0) {
			secret_len = ret;
			return 0;
		}

		return ret;
	}

	return -ENOENT;
}

static int otp_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	int ret;

	ret = settings_subsys_init();
	if (ret) {
		LOG_ERR("Failed to initializing settings subsys: %d", ret);
	}

	ret = settings_load_subtree_direct("app/otp", otp_settings_load_cb, NULL);
	if (ret) {
		LOG_ERR("Failed to load otp settings: %d", ret);
	}

	return 0;
}

SYS_INIT(otp_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
#endif
