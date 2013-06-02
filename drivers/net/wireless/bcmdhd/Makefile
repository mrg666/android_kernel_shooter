# bcmdhd
#DHDCFLAGS = -Wall -Wstrict-prototypes -Dlinux -DBCMDRIVER                     \
	-DBCMDONGLEHOST -DUNRELEASEDCHIP -DBCMDMA32 -DWLBTAMP -DBCMFILEIMAGE  \
	-DDHDTHREAD -DDHD_SCHED -DDHD_DEBUG -DSDTEST -DBDC -DTOE    \
	-DDHD_BCMEVENTS -DSHOW_EVENTS -DDONGLEOVERLAYS -DBCMDBG               \
	-DCUSTOMER_HW2 -DCUSTOM_OOB_GPIO_NUM=2 -DOOB_INTR_ONLY -DHW_OOB       \
	-DMMC_SDIO_ABORT -DBCMSDIO -DBCMLXSDMMC -DBCMPLATFORM_BUS -DWLP2P     \
	-DNEW_COMPAT_WIRELESS -DWIFI_ACT_FRAME -DARP_OFFLOAD_SUPPORT          \
	-DKEEP_ALIVE -DCSCAN -DGET_CUSTOM_MAC_ENABLE -DPKT_FILTER_SUPPORT     \
	-DEMBEDDED_PLATFORM -DENABLE_INSMOD_NO_FW_LOAD -DPNO_SUPPORT          \
	-Idrivers/net/wireless/bcmdhd -Idrivers/net/wireless/bcmdhd/include

DHDCFLAGS = -DLINUX -DBCMDRIVER -DBCMDONGLEHOST -DUNRELEASEDCHIP -DBCMDMA32  \
	-DBCMFILEIMAGE -Dlinux -DDHD_SDALIGN=64 -DMAX_HDR_READ=64 -DCSCAN    \
	-DDHD_FIRSTREAD=64 -DDHDTHREAD -DDHD_SCHED -DOEM_ANDROID -DBCMDBG    \
	-DTOE -DDHD_BCMEVENTS -DSHOW_EVENTS -DDONGLEOVERLAYS -DKEEP_ALIVE    \
	-DCONFIG_FIRST_SCAN -DAPSTA_CONCURRENT -DWLP2P -DARP_OFFLOAD_SUPPORT \
	-DBRCM_WPSAP -DCUSTOM_OOB_GPIO_NUM=46 -DOOB_INTR_ONLY -DPNO_SUPPORT  \
	-DMMC_SDIO_ABORT -DEMBEDDED_PLATFORM -DCUSTOMER_HW2 -DBCMSDIO -DBDC  \
	-DBCMLXSDMMC -DBCMPLATFORM_BUS -DWIFI_ACT_FRAME -DPKT_FILTER_SUPPORT \
	-DWL_CFG80211 -DWL_COMPAT_WIRELESS -DENABLE_INSMOD_NO_FW_LOAD        \
	-Wall -Wstrict-prototypes -Werror                                    \
	-Idrivers/net/wireless/bcmdhd -Idrivers/net/wireless/bcmdhd/include


CFLAGS_wl_cfgp2p.o = -Wno-sizeof-pointer-memaccess
DHDOFILES = aiutils.o bcmsdh_sdmmc_linux.o dhd_linux.o siutils.o bcmutils.o   \
	dhd_linux_sched.o bcmwifi.o dhd_sdio.o bcmevent.o dhd_bta.o hndpmu.o  \
	bcmsdh.o dhd_cdc.o bcmsdh_linux.o dhd_common.o linux_osl.o            \
	bcmsdh_sdmmc.o dhd_custom_gpio.o sbutils.o wldev_common.o wl_android.o dhd_cfg80211.o

obj-$(CONFIG_BCMDHD) += bcmdhd.o
bcmdhd-objs += $(DHDOFILES)
ifneq ($(CONFIG_WIRELESS_EXT),)
bcmdhd-objs += wl_iw.o
DHDCFLAGS += -DSOFTAP
endif
ifneq ($(CONFIG_CFG80211),)
bcmdhd-objs += wl_cfg80211.o wl_cfgp2p.o wl_linux_mon.o
DHDCFLAGS += -DWL_CFG80211
endif
EXTRA_CFLAGS = $(DHDCFLAGS)
ifeq ($(CONFIG_BCMDHD),m)
EXTRA_LDFLAGS += --strip-debug
endif
