/* Copyright (c) 2012, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/mutex.h>
#include <linux/msm_tsens.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>

#define DEF_TEMP_SENSOR      0

//max thermal limit
#define DEF_ALLOWED_MAX_HIGH 70
#define DEF_ALLOWED_MAX_FREQ 972000

//Sampling interval
#define DEF_THERMAL_CHECK_MS 1000

static int enabled;

static struct delayed_work check_temp_work;

static struct msm_thermal_tuners {
	unsigned int allowed_max_high;
	unsigned int allowed_max_low;
	unsigned int allowed_max_freq;
	unsigned int check_interval_ms;
} msm_thermal_tuners_ins = {
	.allowed_max_high = DEF_ALLOWED_MAX_HIGH,
	.allowed_max_low = (DEF_ALLOWED_MAX_HIGH - 10),
	.allowed_max_freq = DEF_ALLOWED_MAX_FREQ,
	.check_interval_ms = DEF_THERMAL_CHECK_MS,
};

static int update_cpu_max_freq(struct cpufreq_policy *cpu_policy,
			       int cpu, int max_freq)
{
	int ret = 0;

	if (!cpu_policy)
		return -EINVAL;

	cpufreq_verify_within_limits(cpu_policy,
				cpu_policy->min, max_freq);
	cpu_policy->user_policy.max = max_freq;

	ret = cpufreq_update_policy(cpu);
	if (!ret)
		pr_info("msm_thermal: Limiting core%d max frequency to %d\n",
			cpu, max_freq);

	return ret;
}

static void check_temp(struct work_struct *work)
{
	struct cpufreq_policy *cpu_policy = NULL;
	struct tsens_device tsens_dev;
	unsigned long temp = 0;
	unsigned int max_freq = 0;
	int update_policy = 0;
	int cpu = 0;
	int ret = 0;

	tsens_dev.sensor_num = DEF_TEMP_SENSOR;
	ret = tsens_get_temp(&tsens_dev, &temp);
	if (ret) {
		pr_err("msm_thermal: Unable to read TSENS sensor %d\n",
				tsens_dev.sensor_num);
		goto reschedule;
	}

	for_each_possible_cpu(cpu) {
		update_policy = 0;
		cpu_policy = cpufreq_cpu_get(cpu);
		if (!cpu_policy) {
			pr_debug("msm_thermal: NULL policy on cpu %d\n", cpu);
			continue;
		}
		if (temp >= msm_thermal_tuners_ins.allowed_max_high) {
			if (cpu_policy->max > msm_thermal_tuners_ins.allowed_max_freq) {
				update_policy = 1;
				max_freq = msm_thermal_tuners_ins.allowed_max_freq;
			} else {
				pr_debug("msm_thermal: policy max for cpu %d "
					 "already < allowed_max_freq\n", cpu);
			}
		} else if (temp < msm_thermal_tuners_ins.allowed_max_low) {
			if (cpu_policy->max < cpu_policy->cpuinfo.max_freq) {
				max_freq = cpu_policy->cpuinfo.max_freq;
				update_policy = 1;
			} else {
				pr_debug("msm_thermal: policy max for cpu %d "
					 "already at max allowed\n", cpu);
			}
		}

		if (update_policy)
			update_cpu_max_freq(cpu_policy, cpu, max_freq);

		cpufreq_cpu_put(cpu_policy);
	}

reschedule:
	if (enabled)
		schedule_delayed_work(&check_temp_work,
				msecs_to_jiffies(msm_thermal_tuners_ins.check_interval_ms));
}

static void disable_msm_thermal(void)
{
	int cpu = 0;
	struct cpufreq_policy *cpu_policy = NULL;

	/* make sure check_temp is no longer running */
	cancel_delayed_work(&check_temp_work);
	flush_scheduled_work();

	for_each_possible_cpu(cpu) {
		cpu_policy = cpufreq_cpu_get(cpu);
		if (cpu_policy) {
			if (cpu_policy->max < cpu_policy->cpuinfo.max_freq)
				update_cpu_max_freq(cpu_policy, cpu,
						    cpu_policy->
						    cpuinfo.max_freq);
			cpufreq_cpu_put(cpu_policy);
		}
	}
}

static int set_enabled(const char *val, const struct kernel_param *kp)
{
	int ret = 0;

	ret = param_set_bool(val, kp);
	if (enabled) {
		schedule_delayed_work(&check_temp_work,
			msecs_to_jiffies(msm_thermal_tuners_ins.check_interval_ms));
		pr_info("msm_thermal: enabled = %d\n", enabled);
	} else {
		disable_msm_thermal();
		pr_info("msm_thermal: disabled = %d\n", enabled);
	}	

	return ret;
}

static struct kernel_param_ops module_ops = {
	.set = set_enabled,
	.get = param_get_bool,
};

module_param_cb(enabled, &module_ops, &enabled, 0644);
MODULE_PARM_DESC(enabled, "enforce thermal limit on cpu");

/**************************** SYSFS START ****************************/
struct kobject *msm_thermal_kobject;

#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)               \
{									\
	return sprintf(buf, "%u\n", msm_thermal_tuners_ins.object);				\
}

show_one(allowed_max_high, allowed_max_high);
show_one(allowed_max_low, allowed_max_low);
show_one(allowed_max_freq, allowed_max_freq);
show_one(check_interval_ms, check_interval_ms);

static ssize_t store_allowed_max_high(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_max_high = input;

	return count;
}

static ssize_t store_allowed_max_low(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_max_low = input;

	return count;
}

static ssize_t store_allowed_max_freq(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.allowed_max_freq = input;

	return count;
}

static ssize_t store_check_interval_ms(struct kobject *a, struct attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_thermal_tuners_ins.check_interval_ms = input;

	return count;
}


define_one_global_rw(allowed_max_high);
define_one_global_rw(allowed_max_low);
define_one_global_rw(allowed_max_freq);
define_one_global_rw(check_interval_ms);

static struct attribute *msm_thermal_attributes[] = {
	&allowed_max_high.attr,
	&allowed_max_low.attr,
	&allowed_max_freq.attr,
	&check_interval_ms.attr,
	NULL
};


static struct attribute_group msm_thermal_attr_group = {
	.attrs = msm_thermal_attributes,
	.name = "conf",
};
/**************************** SYSFS END ****************************/

static int __init msm_thermal_init(void)
{
	int rc, ret = 0;

	enabled = 1;
	INIT_DELAYED_WORK(&check_temp_work, check_temp);

	schedule_delayed_work(&check_temp_work, 0);

	msm_thermal_kobject = kobject_create_and_add("msm_thermal", kernel_kobj);
	if (msm_thermal_kobject) {
		rc = sysfs_create_group(msm_thermal_kobject,
							&msm_thermal_attr_group);
		if (rc) 
			pr_warn("msm_thermal: sysfs: ERROR, could not create sysfs group");
		else
			pr_warn("msm_thermal: initialized");
	} else
		pr_warn("msm_thermal: sysfs: ERROR, could not create sysfs kobj");

	return ret;
}
fs_initcall(msm_thermal_init);

