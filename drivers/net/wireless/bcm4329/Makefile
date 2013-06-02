# bcm4329

DHDCFLAGS = -DLINUX -DBCMDRIVER -DBCMDONGLEHOST -DDHDTHREAD -DBCMWPA2 -DCSCAN \
	-DUNRELEASEDCHIP -Dlinux -DDHD_SDALIGN=64 -DMAX_HDR_READ=64 -DSOFTAP  \
	-DDHD_FIRSTREAD=64 -DDHD_GPL -DDHD_SCHED -DBDC -DTOE -DDHD_BCMEVENTS  \
	-DSHOW_EVENTS -DBCMSDIO -DBCMLXSDMMC -DBCMPLATFORM_BUS -DPNO_SUPPORT  \
	-DOOB_INTR_ONLY -DCUSTOMER_HW2 -DMMC_SDIO_ABORT -DDHD_DEBUG_TRAP      \
	-DDHD_USE_STATIC_BUF -DKEEP_ALIVE -DCONFIG_FIRST_SCAN -DAP_ONLY       \
	-DEMBEDDED_PLATFORM -DARP_OFFLOAD_SUPPORT -DPKT_FILTER_SUPPORT        \
	-Wall -Wstrict-prototypes -Werror                                     \
	-Idrivers/net/wireless/bcm4329 -Idrivers/net/wireless/bcm4329/include

DHDOFILES = dhd_linux.o linux_osl.o bcmutils.o dhd_common.o dhd_custom_gpio.o \
	wl_iw.o siutils.o sbutils.o aiutils.o hndpmu.o bcmwifi.o dhd_sdio.o   \
	dhd_linux_sched.o dhd_cdc.o bcmsdh_sdmmc.o bcmsdh.o bcmsdh_linux.o    \
	bcmsdh_sdmmc_linux.o

obj-$(CONFIG_BCM4329) += bcm4329.o
bcm4329-objs += $(DHDOFILES)
EXTRA_CFLAGS = $(DHDCFLAGS)
EXTRA_LDFLAGS += --strip-debug
