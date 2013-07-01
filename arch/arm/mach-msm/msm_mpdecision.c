/*
 * arch/arm/mach-msm/msm_mpdecision.c
 *
 * This program features:
 * -cpu auto-hotplug/unplug based on system load for MSM multicore cpus
 * -single core while screen is off
 * -extensive sysfs tuneables
 *
 * Copyright (c) 2012-2013, Dennis Rassmann <showp1984@gmail.com>
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

enum {
	MSM_MPDEC_DISABLED = 0,
	MSM_MPDEC_IDLE,
	MSM_MPDEC_DOWN,
	MSM_MPDEC_UP,
};

struct msm_mpdec_cpudata_t {
	struct mutex hotplug_mutex;
	int online;
	int device_suspended;
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
	unsigned int startdelay;
	unsigned int delay;
	unsigned int pause;
	bool scroff_single_core;
	unsigned long int idle_freq;
	unsigned int max_cpus;
	unsigned int min_cpus;
} msm_mpdec_tuners_ins = {
	.startdelay = MSM_MPDEC_STARTDELAY,
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
extern unsigned long acpuclk_get_rate(int);

unsigned int state = MSM_MPDEC_DISABLED;
bool was_paused = false;
static cputime64_t mpdec_paused_until = 0;

static unsigned long get_rate(int cpu) {
	return acpuclk_get_rate(cpu);
}

static int get_slowest_cpu(void) {
	int i, cpu = 0;
	unsigned long rate, slow_rate = 0;

	for (i = 1; i < CONFIG_NR_CPUS; i++) {
		if (!cpu_online(i))
			continue;
		rate = get_rate(i);
		if (slow_rate == 0)
			slow_rate = rate;

		if ((rate <= slow_rate) && (slow_rate != 0)) {
			cpu = i;
			slow_rate = rate;
		}
	}

	return cpu;
}

static unsigned long get_slowest_cpu_rate(void) {
	int i = 0;
	unsigned long rate, slow_rate = 0;

	for (i = 0; i < CONFIG_NR_CPUS; i++) {
		if (!cpu_online(i))
			continue;
		rate = get_rate(i);
		if ((rate < slow_rate) && (slow_rate != 0))
			slow_rate = rate;
		if (slow_rate == 0)
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

static int mp_decision(void) {
	static bool first_call = true;
	int new_state = MSM_MPDEC_IDLE;
	int nr_cpu_online;
	int index;
	unsigned int rq_depth;
	static cputime64_t total_time = 0;
	static cputime64_t last_time;
	cputime64_t current_time;
	cputime64_t this_time = 0;

	if (state == MSM_MPDEC_DISABLED)
		return MSM_MPDEC_DISABLED;

	current_time = ktime_to_ms(ktime_get());
	if (current_time <= msm_mpdec_tuners_ins.startdelay)
		return MSM_MPDEC_IDLE;

	/* this effectively disables mpdecision when screen is on
	 * so there is no need to continue */
	if (msm_mpdec_tuners_ins.min_cpus == CONFIG_NR_CPUS)
		return MSM_MPDEC_IDLE;
	
	if (first_call) 
		first_call = false;
	else 
		this_time = current_time - last_time;
	
	total_time += this_time;

	rq_depth = get_rq_info();
	nr_cpu_online = num_online_cpus();

	if (nr_cpu_online) {
		index = (nr_cpu_online - 1) * 2;
		if ((nr_cpu_online < msm_mpdec_tuners_ins.max_cpus) && 
		    (rq_depth >= NwNs_Threshold[index])) {
			if (total_time >= TwTs_Threshold[index]) {
				new_state = MSM_MPDEC_UP;
				if (get_slowest_cpu_rate() <= msm_mpdec_tuners_ins.idle_freq)
					new_state = MSM_MPDEC_IDLE;
			}
		} else if ((nr_cpu_online > msm_mpdec_tuners_ins.min_cpus) &&
			   (rq_depth <= NwNs_Threshold[index+1])) {
			if (total_time >= TwTs_Threshold[index+1]) {
				new_state = MSM_MPDEC_DOWN;
				if (get_slowest_cpu_rate() > msm_mpdec_tuners_ins.idle_freq)
					new_state = MSM_MPDEC_IDLE;
			}
		} else {
			new_state = MSM_MPDEC_IDLE;
			total_time = 0;
		}
	} else
		total_time = 0;

	if (new_state != MSM_MPDEC_IDLE)
		total_time = 0;

	last_time = ktime_to_ms(ktime_get());
#if DEBUG
	pr_info(MPDEC_TAG"[DEBUG] rq: %u, new_state: %i | Mask=[%d%d]\n",
		rq_depth, new_state, cpu_online(0), cpu_online(1));
#endif
	return new_state;
}

static void msm_mpdec_work_thread(struct work_struct *work) {
	unsigned int cpu = nr_cpu_ids;
	bool suspended = false;

	if (ktime_to_ms(ktime_get()) <= msm_mpdec_tuners_ins.startdelay)
		goto out;

	/* Check if we are paused */
	if (mpdec_paused_until >= ktime_to_ms(ktime_get()))
		goto out;

	for_each_possible_cpu(cpu) {
		if ((per_cpu(msm_mpdec_cpudata, cpu).device_suspended == true)) {
			suspended = true;
			break;
		}
	}
	if (suspended == true)
		goto out;

	if (!mutex_trylock(&mpdec_msm_cpu_lock))
		goto out;

	/* if sth messed with the cpus, update the check vars so we can proceed */
	if (was_paused) {
		for_each_possible_cpu(cpu) {
			if (cpu_online(cpu))
				per_cpu(msm_mpdec_cpudata, cpu).online = true;
			else if (!cpu_online(cpu))
				per_cpu(msm_mpdec_cpudata, cpu).online = false;
		}
		was_paused = false;
	}

	state = mp_decision();
	switch (state) {
	case MSM_MPDEC_DISABLED:
	case MSM_MPDEC_IDLE:
		break;
	case MSM_MPDEC_DOWN:
		cpu = get_slowest_cpu();
		if (cpu < nr_cpu_ids) {
			if (per_cpu(msm_mpdec_cpudata, cpu).online == true) {
				if (!mpdec_cpu_down(cpu)) {
					pr_info(MPDEC_TAG"CPU[%d] bypassed mpdecision! | pausing [%d]ms\n",
						cpu, msm_mpdec_tuners_ins.pause);
					mpdec_paused_until = ktime_to_ms(ktime_get()) + 
						msm_mpdec_tuners_ins.pause;
					was_paused = true;
				}
			}
		}
		break;
	case MSM_MPDEC_UP:
		cpu = cpumask_next_zero(0, cpu_online_mask);
		if (cpu < nr_cpu_ids) {
			if (per_cpu(msm_mpdec_cpudata, cpu).online == false) {
				if (!mpdec_cpu_up(cpu)) {
					pr_info(MPDEC_TAG"CPU[%d] bypassed mpdecision! | pausing [%d]ms\n",
						cpu, msm_mpdec_tuners_ins.pause);
					mpdec_paused_until = ktime_to_ms(ktime_get()) + 
						msm_mpdec_tuners_ins.pause;
					was_paused = true;
				}
			}
		}
		break;
	default:
		pr_err(MPDEC_TAG"%s: invalid mpdec hotplug state %d\n",
			__func__, state);
	}
	mutex_unlock(&mpdec_msm_cpu_lock);

out:
	if (state != MSM_MPDEC_DISABLED)
		queue_delayed_work(msm_mpdec_workq, &msm_mpdec_work,
				   msecs_to_jiffies(msm_mpdec_tuners_ins.delay));
	return;
}

static void msm_mpdec_early_suspend(struct early_suspend *h) {
	int cpu = nr_cpu_ids;

	if (!msm_mpdec_tuners_ins.scroff_single_core) {
		pr_info(MPDEC_TAG"Screen -> off\n");
		return;
	}

	/* main work thread can sleep now */
	cancel_delayed_work_sync(&msm_mpdec_work);
	
	for (cpu = 1; cpu < CONFIG_NR_CPUS; cpu++) {
		mpdec_cpu_down(cpu);
		per_cpu(msm_mpdec_cpudata, cpu).device_suspended = true;
	}

	pr_info(MPDEC_TAG"Screen -> off. Deactivated mpdecision.\n");
}

static void msm_mpdec_late_resume(struct early_suspend *h) {
	int cpu = nr_cpu_ids;

	if (!msm_mpdec_tuners_ins.scroff_single_core) {
		pr_info(MPDEC_TAG"Screen -> on\n");
		return;
	}

	for (cpu = 1; cpu < CONFIG_NR_CPUS; cpu++) {
		mpdec_cpu_up(cpu);
		per_cpu(msm_mpdec_cpudata, cpu).device_suspended = false;
	}

	/* wake up main work thread */
	was_paused = true;
	queue_delayed_work(msm_mpdec_workq, &msm_mpdec_work, 0);

	pr_info(MPDEC_TAG"Screen -> on. Activated mpdecision. | Mask=[%d%d]\n",
		cpu_online(0), cpu_online(1));
}

static struct early_suspend msm_mpdec_early_suspend_handler = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN,
	.suspend = msm_mpdec_early_suspend,
	.resume = msm_mpdec_late_resume,
};

/**************************** SYSFS START ****************************/
struct kobject *msm_mpdec_kobject;

#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%u\n", msm_mpdec_tuners_ins.object);	\
}

show_one(startdelay, startdelay);
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

static ssize_t show_idle_freq (struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	return sprintf(buf, "%lu\n", msm_mpdec_tuners_ins.idle_freq);
}

static ssize_t show_enabled(struct kobject *a, struct attribute *b,
				char *buf)
{
	unsigned int enabled;
	switch (state) {
	case MSM_MPDEC_DISABLED:
		enabled = 0;
		break;
	case MSM_MPDEC_IDLE:
	case MSM_MPDEC_DOWN:
	case MSM_MPDEC_UP:
		enabled = 1;
		break;
	default:
		enabled = 333;
	}
	return sprintf(buf, "%u\n", enabled);
}

static ssize_t store_startdelay(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_mpdec_tuners_ins.startdelay = input;

	return count;
}

static ssize_t store_delay(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_mpdec_tuners_ins.delay = input;

	return count;
}

static ssize_t store_pause(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	msm_mpdec_tuners_ins.pause = input;

	return count;
}

static ssize_t store_idle_freq(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	long unsigned int input;
	int ret;
	ret = sscanf(buf, "%lu", &input);
	if (ret != 1)
		return -EINVAL;

	msm_mpdec_tuners_ins.idle_freq = input;

	return count;
}

static ssize_t store_scroff_single_core(struct kobject *a, struct attribute *b,
					const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;
	switch (buf[0]) {
	case '0':
		msm_mpdec_tuners_ins.scroff_single_core = input;
		break;
	case '1':
		msm_mpdec_tuners_ins.scroff_single_core = input;
		break;
	default:
		ret = -EINVAL;
	}
	return count;
}

static ssize_t store_max_cpus(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;
	if ((input < 1) || (input > CONFIG_NR_CPUS) || 
		(input < msm_mpdec_tuners_ins.min_cpus))
		return -EINVAL;

	msm_mpdec_tuners_ins.max_cpus = input;

	return count;
}

static ssize_t store_min_cpus(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	
	if (ret != 1) 
		return -EINVAL;
	if ((input < 1) || (input > CONFIG_NR_CPUS) || 
		(input > msm_mpdec_tuners_ins.max_cpus))
		return -EINVAL;
	
	msm_mpdec_tuners_ins.min_cpus = input;

	return count;
}

static ssize_t store_enabled(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int cpu, input, enabled;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	switch (state) {
	case MSM_MPDEC_DISABLED:
		enabled = 0;
		break;
	case MSM_MPDEC_IDLE:
	case MSM_MPDEC_DOWN:
	case MSM_MPDEC_UP:
		enabled = 1;
		break;
	default:
		enabled = 333;
	}

	if (buf[0] == enabled)
		return -EINVAL;

	switch (buf[0]) {
	case '0':
		state = MSM_MPDEC_DISABLED;
		cancel_delayed_work_sync(&msm_mpdec_work);
		for (cpu = 1; cpu < CONFIG_NR_CPUS; cpu++)
			mpdec_cpu_up(cpu);
		pr_info(MPDEC_TAG"msm_mpdecision disabled\n");
		break;
	case '1':
		state = MSM_MPDEC_IDLE;
		was_paused = true;
		queue_delayed_work(msm_mpdec_workq, &msm_mpdec_work,
				msecs_to_jiffies(msm_mpdec_tuners_ins.delay));
		pr_info(MPDEC_TAG"msm_mpdecision enabled\n");
		break;
	default:
		ret = -EINVAL;
	}
	return count;
}

define_one_global_rw(startdelay);
define_one_global_rw(delay);
define_one_global_rw(pause);
define_one_global_rw(scroff_single_core);
define_one_global_rw(idle_freq);
define_one_global_rw(min_cpus);
define_one_global_rw(max_cpus);
define_one_global_rw(enabled);

static struct attribute *msm_mpdec_attributes[] = {
	&startdelay.attr,
	&delay.attr,
	&pause.attr,
	&scroff_single_core.attr,
	&idle_freq.attr,
	&min_cpus.attr,
	&max_cpus.attr,
	&enabled.attr,
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
				char *buf)
{
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
					char *buf)
{
	ssize_t len = 0;
	int cpu = 0;

	for_each_possible_cpu(cpu) {
		len += sprintf(buf + len, "%i %llu\n", cpu, per_cpu(msm_mpdec_cpudata, cpu).times_cpu_hotplugged);
	}

	return len;
}
define_one_global_ro(times_cpus_hotplugged);

static ssize_t show_times_cpus_unplugged(struct kobject *a, struct attribute *b,
					char *buf)
{
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
		per_cpu(msm_mpdec_cpudata, cpu).device_suspended = false;
		per_cpu(msm_mpdec_cpudata, cpu).online = true;
		per_cpu(msm_mpdec_cpudata, cpu).on_time_total = 0;
		per_cpu(msm_mpdec_cpudata, cpu).times_cpu_unplugged = 0;
		per_cpu(msm_mpdec_cpudata, cpu).times_cpu_hotplugged = 0;
	}

	was_paused = true;

	msm_mpdec_workq = alloc_workqueue("mpdec",
					WQ_UNBOUND | WQ_RESCUER | WQ_FREEZABLE, 1);
	if (!msm_mpdec_workq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&msm_mpdec_work, msm_mpdec_work_thread);
	if (state != MSM_MPDEC_DISABLED)
		queue_delayed_work(msm_mpdec_workq, &msm_mpdec_work,
				   msecs_to_jiffies(msm_mpdec_tuners_ins.delay));

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

void msm_mpdec_exit(void) {
	destroy_workqueue(msm_mpdec_workq);
	destroy_workqueue(msm_mpdec_workq);
}

