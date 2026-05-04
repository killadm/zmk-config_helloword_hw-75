/*
 * Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

#include <app/settings_work.h>

#define SETTINGS_WORK_NAME_MAX 24
#define SETTINGS_WORK_VALUE_MAX 56

struct settings_work_request {
	struct k_work work;
	struct k_sem done;
	struct k_mutex lock;
	const char *name;
	const void *value;
	size_t val_len;
	int result;
};

static struct settings_work_request request;

static void settings_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	if (request.value == NULL || request.val_len == 0) {
		request.result = settings_delete(request.name);
	} else {
		request.result = settings_save_one(request.name, request.value, request.val_len);
	}

	k_sem_give(&request.done);
}

static int settings_work_submit(const char *name, const void *value, size_t val_len)
{
	if (!name || strlen(name) >= SETTINGS_WORK_NAME_MAX || val_len > SETTINGS_WORK_VALUE_MAX) {
		return -EINVAL;
	}
	if (k_current_get() == k_work_queue_thread_get(&k_sys_work_q)) {
		return (value == NULL || val_len == 0) ? settings_delete(name) :
							 settings_save_one(name, value, val_len);
	}

	k_mutex_lock(&request.lock, K_FOREVER);

	request.name = name;
	request.value = value;
	request.val_len = val_len;
	request.result = -EINPROGRESS;
	k_sem_reset(&request.done);

	int ret = k_work_submit_to_queue(&k_sys_work_q, &request.work);
	if (ret < 0) {
		k_mutex_unlock(&request.lock);
		return ret;
	}

	k_sem_take(&request.done, K_FOREVER);
	ret = request.result;

	k_mutex_unlock(&request.lock);
	return ret;
}

int hw75_settings_save_one(const char *name, const void *value, size_t val_len)
{
	return settings_work_submit(name, value, val_len);
}

int hw75_settings_delete(const char *name)
{
	return settings_work_submit(name, NULL, 0);
}

static int settings_work_init(const struct device *dev)
{
	ARG_UNUSED(dev);

	k_work_init(&request.work, settings_work_handler);
	k_sem_init(&request.done, 0, 1);
	k_mutex_init(&request.lock);

	return 0;
}

SYS_INIT(settings_work_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
