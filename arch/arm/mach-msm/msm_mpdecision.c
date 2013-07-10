/*
 * arch/arm/mach-msm/msm_mpdecision.c
 *
 * This program features:
 * -cpu auto-hotplug/unplug based on system load for MSM multicore cpus
 * -single core while screen is off
 * -extensive sysfs tuneables
 *
 * Copyright (c) 2012-2013, Dennis Rassmann <showp1984@gmail.com>
 * revised by mrg666, 2013, https://github.com/mrg666/android_kernel_shooter
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/earlysuspend.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <asm-generic/cputime.h>
#include <linux/hrtimer.h>
#include <linux/delay.h>
#include "acpuclock.h"

#define DEBUG 0

#define MPDEC_TAG                       "[MPDEC]: "
#define MSM_MPDEC_STARTDELAY            20000
#define MSM_MPDEC_DELAY                 100
#define MSM_MPDEC_PAUSE                 10000
#define MSM_MPDEC_IDLE_FREQ             384000

struct global_attr {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj,
			struct attribute *attr, char *buf);
	ssize_t (*store)(struct kobject *a, struct attribute *b,
			 const char *c, size_t count);
};

#define define_one_global_ro(_name)		\
static struct global_attr _name =		\
__ATTR(_name, 0444, show_##_name, NULL)

#define define_one_global_rw(_name)		\
static struct global_attr _name =		\
__ATTR(_name, 0644, show_##_name, store_##_name)

struct msm_mpdec_cpudata_t {
	struct mutex hotplug_mutex;
	int online;
	cputime64_t on_time;
	cputime64_t on_time_total;
	long long unsigned int times_cpu_hotplugged;
	long long unsigned int times_cpu_unplugged;
};
static DEFINE_PER_CPU(struct msm_mpdec_cpudata_t, msm_mpdec_cpudata);

static struct delayed_work msm_mpdec_work;
static struct workqueue_struct *msm_mpdec_workq;
static DEFINE_MUTEX(mpdec_msm_cpu_lock);

static struct msm_mpdec_tuners {
	unsigned int delay;
	unsigned int pause;
	bool scroff_single_core;
	unsigned long int idle_freq;
	unsigned int max_cpus;
	unsigned int min_cpus;
} msm_mpdec_tuners_ins = {
	.delay = MSM_MPDEC_DELAY,
	.pause = MSM_MPDEC_PAUSE,
	.scroff_single_core = true,
	.idle_freq = MSM_MPDEC_IDLE_FREQ,
	.max_cpus = CONFIG_NR_CPUS,
	.min_cpus = 1,
};

static unsigned int NwNs_Threshold[4] = {35, 0, 0, 5};
static unsigned int TwTs_Threshold[4] = {250, 0, 0, 250};

extern unsigned int get_rq_info(void);

bool was_paused = false;
static cputime64_t mpdec_paused_until = 0;
static cputime64_t total_time = 0;
static cputime64_t last_time;
static int enabled = 1;

static void mpdec_pause(int cpu) {
	pr_info(MPDEC_TAG"CPU[%d] bypassed mpdecision! | pausing [%d]ms\n",
		cpu, msm_mpdec_tuners_ins.pause);
	mpdec_paused_until = ktime_to_ms(ktime_get()) + msm_mpdec_tuners_ins.pause;
	was_paused = true;
}

static int get_slowest_cpu(void) {
	int i, cpu = 1;
	unsigned long rate, slow_rate = 999999999;

	for (i = 1; i < nr_cpu_ids; i++) {
		if (!cpu_online(i))
			continue;
		rate = acpuclk_get_rate(i);
		if (rate < slow_rate) {
			cpu = i;
			slow_rate = rate;
		}
	}

	return cpu;
}

static unsigned long get_slowest_cpu_rate(void) {
	int cpu;
	unsigned long rate, slow_rate = 999999999;

	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		if (!cpu_online(cpu))
			continue;
		rate = acpuclk_get_rate(cpu);
		if (rate < slow_rate) 
			slow_rate = rate;
	}

	return slow_rate;
}

static bool mpdec_cpu_down(int cpu) {
	cputime64_t on_time = 0;
	bool ret;
	
	ret = cpu_online(cpu);
	if (ret) {
		mutex_lock(&per_cpu(msm_mpdec_cpudata, cpu).hotplug_mutex);
		cpu_down(cpu);
		per_cpu(msm_mpdec_cpudata, cpu).online = false;
		on_time = ktime_to_ms(ktime_get()) - 
			per_cpu(msm_mpdec_cpudata, cpu).on_time;
		per_cpu(msm_mpdec_cpudata, cpu).on_time_total += on_time;
		per_cpu(msm_mpdec_cpudata, cpu).times_cpu_unplugged += 1;
		pr_info(MPDEC_TAG"CPU[%d] on->off | Mask=[%d%d] | time online: %llu\n",
		cpu, cpu_online(0), cpu_online(1), on_time);
		mutex_unlock(&per_cpu(msm_mpdec_cpudata, cpu).hotplug_mutex);
	}
	return ret;
}

static bool mpdec_cpu_up(int cpu) {
	bool ret;
	
	ret = !cpu_online(cpu);
	if (ret) {
		mutex_lock(&per_cpu(msm_mpdec_cpudata, cpu).hotplug_mutex);
		cpu_up(cpu);
		per_cpu(msm_mpdec_cpudata, cpu).online = true;
		per_cpu(msm_mpdec_cpudata, cpu).on_time = ktime_to_ms(ktime_get());
		per_cpu(msm_mpdec_cpudata, cpu).times_cpu_hotplugged += 1;
		pr_info(MPDEC_TAG"CPU[%d] off->on | Mask=[%d%d]\n",
			cpu, cpu_online(0), cpu_online(1));
		mutex_unlock(&per_cpu(msm_mpdec_cpudata, cpu).hotplug_mutex);
	}
	return ret;
}

static void msm_mpdec_work_thread(struct work_struct *work) {
	unsigned int cpu = nr_cpu_ids;
	int nr_cpu_online;
	int index;
	unsigned int rq_depth;
	cputime64_t current_time;

	current_time = ktime_to_ms(ktime_get());
	total_time += (current_time - last_time);

	if (was_paused) {
		if (mpdec_paused_until >= current_time) {
			goto out;
		} else {
			for_each_possible_cpu(cpu) {
				if (cpu_online(cpu))
					per_cpu(msm_mpdec_cpudata, cpu).online = true;
				else
					per_cpu(msm_mpdec_cpudata, cpu).online = false;
			}
			was_paused = false;
			mpdec_paused_until = 0;
		}
	}

	rq_depth = get_rq_info();
	nr_cpu_online = num_online_cpus();
	index = (nr_cpu_online - 1) * 2;

	if ((nr_cpu_online < msm_mpdec_tuners_ins.max_cpus) && 
	    (rq_depth >= NwNs_Threshold[index])) {
		if (total_time >= TwTs_Threshold[index]) {
			if (get_slowest_cpu_rate() > msm_mpdec_tuners_ins.idle_freq) {
				cpu = cpumask_next_zero(0, cpu_online_mask);
				if (per_cpu(msm_mpdec_cpudata, cpu).online == false) {
					if (mpdec_cpu_up(cpu))
						total_time = 0;
					else
						mpdec_pause(cpu);
				}
			} 
		}
	} else if ((nr_cpu_online > msm_mpdec_tuners_ins.min_cpus) &&
		   (rq_depth <= NwNs_Threshold[index+1])) {
		if (total_time >= TwTs_Threshold[index+1]) {
			if (get_slowest_cpu_rate() <= msm_mpdec_tuners_ins.idle_freq) {
				cpu = get_slowest_cpu();
				if (per_cpu(msm_mpdec_cpudata, cpu).online == true) {
					if (mpdec_cpu_down(cpu))
						total_time = 0;
					else
						mpdec_pause(cpu);
				}
			}
		}
	}
	
out:
	last_time = current_time;
	if (enabled)
		queue_delayed_work(msm_mpdec_workq, &msm_mpdec_work,
				   msecs_to_jiffies(msm_mpdec_tuners_ins.delay));
	return;
}

static void msm_mpdec_early_suspend(struct early_suspend *h) {
	int cpu;

	/* unplug cpu cores */
	if (msm_mpdec_tuners_ins.scroff_single_core)
		for (cpu = 1; cpu < nr_cpu_ids; cpu++)
			mpdec_cpu_down(cpu);

	/* suspend main work thread */
	if (enabled)
		cancel_delayed_work_sync(&msm_mpdec_work);

	pr_info(MPDEC_TAG"msm_mpdecision suspended.\n");
}

static void msm_mpdec_late_resume(struct early_suspend *h) {
	int cpu;

	/* hotplug cpu cores */
	if (msm_mpdec_tuners_ins.scroff_single_core)
		for (cpu = 1; cpu < nr_cpu_ids; cpu++)
			mpdec_cpu_up(cpu);

	/* resume main work thread */
	if (enabled) {
		was_paused = true;
		queue_delayed_work(msm_mpdec_workq, &msm_mpdec_work, 
				msecs_to_jiffies(msm_mpdec_tuners_ins.delay));
	}

	pr_info(MPDEC_TAG"msm_mpdecision resumed. | Mask=[%d%d]\n",
		cpu_online(0), cpu_online(1));
}

static struct early_suspend msm_mpdec_early_suspend_handler = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN,
	.suspend = msm_mpdec_early_suspend,
	.resume = msm_mpdec_late_resume,
};

static int set_enabled(const char *val, const struct kernel_param *kp) {
	int ret = 0;
	int cpu;

	ret = param_set_bool(val, kp);
	if (enabled) {
		was_paused = true;
		queue_delayed_work(msm_mpdec_workq, &msm_mpdec_work,
				msecs_to_jiffies(msm_mpdec_tuners_ins.delay));
		pr_info(MPDEC_TAG"msm_mpdecision enabled\n");
	} else {
		cancel_delayed_work_sync(&msm_mpdec_work);
		for (cpu = 1; cpu < nr_cpu_ids; cpu++)
			mpdec_cpu_up(cpu);
		pr_info(MPDEC_TAG"msm_mpdecision disabled\n");
	}

	return ret;
}

static struct kernel_param_ops module_ops = {
	.set = set_enabled,
	.get = param_get_bool,
};

module_param_cb(enabled, &module_ops, &enabled, 0644);
MODULE_PARM_DESC(enabled, "hotplug cpu cores based on demand");


/**************************** SYSFS START ****************************/
struct kobject *msm_mpdec_kobject;

#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%u\n", msm_mpdec_tuners_ins.object);	\
}

show_one(delay, delay);
show_one(pause, pause);
show_one(scroff_single_core, scroff_single_core);
show_one(min_cpus, min_cpus);
show_one(max_cpus, max_cpus);

#define show_one_twts(file_name, arraypos)				\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%u\n", TwTs_Threshold[arraypos]);		\
}
show_one_twts(twts_threshold_0, 0);
show_one_twts(twts_threshold_1, 1);
show_one_twts(twts_threshold_2, 2);
show_one_twts(twts_threshold_3, 3);

#define store_one_twts(file_name, arraypos)				\
static ssize_t store_##file_name					\
(struct kobject *a, struct attribute *b, const char *buf, size_t count)	\
{									\
	unsigned int input;						\
	int ret;							\
	ret = sscanf(buf, "%u", &input);				\
	if (ret != 1)							\
		return -EINVAL;						\
	TwTs_Threshold[arraypos] = input;				\
	return count;							\
}									\
define_one_global_rw(file_name);
store_one_twts(twts_threshold_0, 0);
store_one_twts(twts_threshold_1, 1);
store_one_twts(twts_threshold_2, 2);
store_one_twts(twts_threshold_3, 3);

#define show_one_nwns(file_name, arraypos)				\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%u\n", NwNs_Threshold[arraypos]);		\
}
show_one_nwns(nwns_threshold_0, 0);
show_one_nwns(nwns_threshold_1, 1);
show_one_nwns(nwns_threshold_2, 2);
show_one_nwns(nwns_threshold_3, 3);

#define store_one_nwns(file_name, arraypos)				\
static ssize_t store_##file_name					\
(struct kobject *a, struct attribute *b, const char *buf, size_t count)	\
{									\
	unsigned int input;						\
	int ret;							\
	ret = sscanf(buf, "%u", &input);				\
	if (ret != 1)							\
		return -EINVAL;						\
	NwNs_Threshold[arraypos] = input;				\
	return count;							\
}									\
define_one_global_rw(file_name);
store_one_nwns(nwns_threshold_0, 0);
store_one_nwns(nwns_threshold_1, 1);
store_one_nwns(nwns_threshold_2, 2);
store_one_nwns(nwns_threshold_3, 3);

static ssize_t show_idle_freq(struct kobject *kobj, struct attribute *attr,
				char *buf) {
	return sprintf(buf, "%lu\n", msm_mpdec_tuners_ins.idle_freq);
}

static ssize_t store_delay(struct kobject *a, struct attribute *b,
				const char *buf, size_t count) {
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_mpdec_tuners_ins.delay = input;

	return count;
}

static ssize_t store_pause(struct kobject *a, struct attribute *b,
				const char *buf, size_t count) {
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_mpdec_tuners_ins.pause = input;

	return count;
}

static ssize_t store_idle_freq(struct kobject *a, struct attribute *b,
				const char *buf, size_t count) {
	long unsigned int input;
	int ret;

	ret = sscanf(buf, "%lu", &input);
	if (ret != 1)
		return -EINVAL;

	msm_mpdec_tuners_ins.idle_freq = input;

	return count;
}

static ssize_t store_scroff_single_core(struct kobject *a, struct attribute *b,
					const char *buf, size_t count) {
	unsigned int input;
	int ret;
						
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if ((input < 0) || (input > 1))
		return -EINVAL;

	msm_mpdec_tuners_ins.scroff_single_core = input;
	
	return count;
}

static ssize_t store_max_cpus(struct kobject *a, struct attribute *b,
				const char *buf, size_t count) {
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if ((input < 1) || (input > nr_cpu_ids) || 
		(input < msm_mpdec_tuners_ins.min_cpus))
		return -EINVAL;

	msm_mpdec_tuners_ins.max_cpus = input;

	return count;
}

static ssize_t store_min_cpus(struct kobject *a, struct attribute *b,
				const char *buf, size_t count) {
	unsigned int input;
	int ret;
					
	ret = sscanf(buf, "%u", &input);
	if (ret != 1) 
		return -EINVAL;

	if ((input < 1) || (input > nr_cpu_ids) || 
		(input > msm_mpdec_tuners_ins.max_cpus))
		return -EINVAL;
	
	msm_mpdec_tuners_ins.min_cpus = input;

	return count;
}

define_one_global_rw(delay);
define_one_global_rw(pause);
define_one_global_rw(scroff_single_core);
define_one_global_rw(idle_freq);
define_one_global_rw(min_cpus);
define_one_global_rw(max_cpus);

static struct attribute *msm_mpdec_attributes[] = {
	&delay.attr,
	&pause.attr,
	&scroff_single_core.attr,
	&idle_freq.attr,
	&min_cpus.attr,
	&max_cpus.attr,
	&twts_threshold_0.attr,
	&twts_threshold_1.attr,
	&twts_threshold_2.attr,
	&twts_threshold_3.attr,
	&nwns_threshold_0.attr,
	&nwns_threshold_1.attr,
	&nwns_threshold_2.attr,
	&nwns_threshold_3.attr,
	NULL
};

static struct attribute_group msm_mpdec_attr_group = {
	.attrs = msm_mpdec_attributes,
	.name = "conf",
};

/********* STATS START *********/

static ssize_t show_time_cpus_on(struct kobject *a, struct attribute *b,
				char *buf) {
	ssize_t len = 0;
	int cpu = 0;

	for_each_possible_cpu(cpu) {
		if (cpu_online(cpu)) {
			len += sprintf(buf + len, "%i %llu\n", cpu,
				(per_cpu(msm_mpdec_cpudata, cpu).on_time_total +
				(ktime_to_ms(ktime_get()) -
				per_cpu(msm_mpdec_cpudata, cpu).on_time)));
		} else
			len += sprintf(buf + len, "%i %llu\n", cpu, per_cpu(msm_mpdec_cpudata, cpu).on_time_total);
	}

	return len;
}
define_one_global_ro(time_cpus_on);

static ssize_t show_times_cpus_hotplugged(struct kobject *a, struct attribute *b,
					char *buf) {
	ssize_t len = 0;
	int cpu = 0;

	for_each_possible_cpu(cpu) {
		len += sprintf(buf + len, "%i %llu\n", cpu, per_cpu(msm_mpdec_cpudata, cpu).times_cpu_hotplugged);
	}

	return len;
}
define_one_global_ro(times_cpus_hotplugged);

static ssize_t show_times_cpus_unplugged(struct kobject *a, struct attribute *b,
					char *buf) {
	ssize_t len = 0;
	int cpu = 0;

	for_each_possible_cpu(cpu) {
		len += sprintf(buf + len, "%i %llu\n", cpu, per_cpu(msm_mpdec_cpudata, cpu).times_cpu_unplugged);
	}

	return len;
}
define_one_global_ro(times_cpus_unplugged);

static struct attribute *msm_mpdec_stats_attributes[] = {
	&time_cpus_on.attr,
	&times_cpus_hotplugged.attr,
	&times_cpus_unplugged.attr,
	NULL
};

static struct attribute_group msm_mpdec_stats_attr_group = {
	.attrs = msm_mpdec_stats_attributes,
	.name = "stats",
};
/**************************** SYSFS END ****************************/

static int __init msm_mpdec_init(void) {
	int cpu, rc, err = 0;

	for_each_possible_cpu(cpu) {
		mutex_init(&(per_cpu(msm_mpdec_cpudata, cpu).hotplug_mutex));
		per_cpu(msm_mpdec_cpudata, cpu).online = true;
		per_cpu(msm_mpdec_cpudata, cpu).on_time_total = 0;
		per_cpu(msm_mpdec_cpudata, cpu).times_cpu_unplugged = 0;
		per_cpu(msm_mpdec_cpudata, cpu).times_cpu_hotplugged = 0;
	}

	was_paused = true;
	last_time = ktime_to_ms(ktime_get());

	msm_mpdec_workq = alloc_workqueue("mpdec",
					WQ_UNBOUND | WQ_RESCUER | WQ_FREEZABLE, 1);
	if (!msm_mpdec_workq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&msm_mpdec_work, msm_mpdec_work_thread);
	if (enabled)
		queue_delayed_work(msm_mpdec_workq, &msm_mpdec_work,
				   msecs_to_jiffies(MSM_MPDEC_STARTDELAY));

	register_early_suspend(&msm_mpdec_early_suspend_handler);

	msm_mpdec_kobject = kobject_create_and_add("msm_mpdecision", kernel_kobj);
	if (msm_mpdec_kobject) {
		rc = sysfs_create_group(msm_mpdec_kobject,
					&msm_mpdec_attr_group);
		if (rc) 
			pr_warn(MPDEC_TAG"sysfs: ERROR, could not create sysfs group");
		
		rc = sysfs_create_group(msm_mpdec_kobject,
				&msm_mpdec_stats_attr_group);
		if (rc) 
			pr_warn(MPDEC_TAG"sysfs: ERROR, could not create sysfs stats group");
		
	} else
		pr_warn(MPDEC_TAG"sysfs: ERROR, could not create sysfs kobj");

	pr_info(MPDEC_TAG"%s init complete.", __func__);

	return err;
}
late_initcall(msm_mpdec_init);
