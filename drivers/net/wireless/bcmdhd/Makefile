# bcmdhd

DHDCFLAGS = -DLINUX -DBCMDRIVER -DBCMDONGLEHOST -DUNRELEASEDCHIP -DBCMDMA32  \
	-DBCMFILEIMAGE -Dlinux -DDHD_SDALIGN=64 -DMAX_HDR_READ=64 -DCSCAN    \
	-DDHD_FIRSTREAD=64 -DDHDTHREAD -DDHD_SCHED -DOEM_ANDROID  -DWLP2P    \
	-DTOE -DDHD_BCMEVENTS -DSHOW_EVENTS -DDONGLEOVERLAYS -DKEEP_ALIVE    \
	-DCONFIG_FIRST_SCAN -DAPSTA_CONCURRENT -DARP_OFFLOAD_SUPPORT -DBDC   \
	-DBRCM_WPSAP -DCUSTOM_OOB_GPIO_NUM=46 -DOOB_INTR_ONLY -DPNO_SUPPORT  \
	-DMMC_SDIO_ABORT -DEMBEDDED_PLATFORM -DCUSTOMER_HW2 -DBCMSDIO        \
	-DBCMLXSDMMC -DBCMPLATFORM_BUS -DWIFI_ACT_FRAME -DPKT_FILTER_SUPPORT \
	-DWL_CFG80211 -DWL_COMPAT_WIRELESS -DENABLE_INSMOD_NO_FW_LOAD        \
	-Wall -Wstrict-prototypes -Werror -DWL_CFG80211_STA_EVENT            \
	-Idrivers/net/wireless/bcmdhd -Idrivers/net/wireless/bcmdhd/include

CFLAGS_wl_cfgp2p.o = -Wno-sizeof-pointer-memaccess
DHDOFILES = aiutils.o bcmsdh_sdmmc_linux.o dhd_linux.o siutils.o bcmutils.o  \
	dhd_linux_sched.o bcmwifi.o dhd_sdio.o bcmevent.o dhd_bta.o hndpmu.o \
	bcmsdh.o dhd_cdc.o bcmsdh_linux.o dhd_common.o linux_osl.o           \
	bcmsdh_sdmmc.o dhd_custom_gpio.o sbutils.o wldev_common.o            \
	wl_android.o dhd_cfg80211.o

obj-$(CONFIG_BCMDHD) += bcmdhd.o
bcmdhd-objs += $(DHDOFILES)
ifneq ($(CONFIG_WIRELESS_EXT),)
bcmdhd-objs += wl_iw.o
DHDCFLAGS += -DSOFTAP -DWL_WIRELESS_EXT
endif
ifneq ($(CONFIG_CFG80211),)
bcmdhd-objs += wl_cfg80211.o wl_cfgp2p.o wl_linux_mon.o
DHDCFLAGS += -DWL_CFG80211
endif
ifneq ($(CONFIG_DHD_USE_SCHED_SCAN),)
DHDCFLAGS += -DWL_SCHED_SCAN
endif
ifneq ($(CONFIG_DHD_ENABLE_P2P),)
DHDCFLAGS += -DWL_ENABLE_P2P_IF
endif
EXTRA_CFLAGS = $(DHDCFLAGS)
ifeq ($(CONFIG_BCMDHD),m)
EXTRA_LDFLAGS += --strip-debug
endif
