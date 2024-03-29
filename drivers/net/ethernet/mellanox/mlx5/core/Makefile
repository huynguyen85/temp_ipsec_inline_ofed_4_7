# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Mellanox 5th generation network adapters
# (ConnectX series) core & netdev driver
#

subdir-ccflags-y += -I$(src)

obj-$(CONFIG_MLX5_CORE) += mlx5_core.o

#
# mlx5 core basic
#
mlx5_core-y :=	main.o cmd.o debugfs.o fw.o eq.o uar.o pagealloc.o \
		health.o mcg.o cq.o alloc.o qp.o port.o mr.o pd.o \
		transobj.o vport.o sriov.o fs_cmd.o fs_core.o pci_irq.o \
		fs_counters.o rl.o lag.o dev.o events.o wq.o lib/gid.o \
		lib/devcom.o diag/fs_tracepoint.o diag/fw_tracer.o qp_exp.o \
		fw_exp.o sriov_sysfs.o mst_dump.o en_diag.o params.o crdump.o \
		icmd.o capi.o diag/diag_cnt.o eswitch_devlink_compat.o devlink.o

mlx5_core-$(CONFIG_ENABLE_MLX5_FS_DEBUGFS) += fs_debugfs.o
#
# Netdev basic
#
mlx5_core-$(CONFIG_MLX5_CORE_EN) += en_main.o en_common.o en_fs.o en_ethtool.o \
		en_tx.o en_rx.o en_dim.o en_txrx.o en/xdp.o en_stats.o en_sysfs.o en_ecn.o \
		en_selftest.o en/port.o en/monitor_stats.o en/reporter_tx.o \
		en/params.o en_debugfs.o en_sniffer.o ipsec_steering.o

#
# Netdev extra
#
mlx5_core-$(CONFIG_MLX5_EN_ARFS)     += en_arfs.o
mlx5_core-$(CONFIG_MLX5_EN_RXNFC)    += en_fs_ethtool.o
mlx5_core-$(CONFIG_MLX5_CORE_EN_DCB) += en_dcbnl.o en/port_buffer.o
mlx5_core-$(CONFIG_MLX5_ESWITCH)     += en_rep.o en_tc.o en/tc_tun.o lib/port_tun.o lag_mp.o \
					miniflow.o miniflow_aging.o

#
# Core extra
#
mlx5_core-$(CONFIG_MLX5_ESWITCH)   += eswitch.o eswitch_offloads.o ecpf.o rdma.o
mlx5_core-$(CONFIG_MLX5_MPFS)      += lib/mpfs.o
ifneq ($(CONFIG_VXLAN),)
	mlx5_core-y		+= lib/vxlan.o
endif
ifneq ($(CONFIG_PTP_1588_CLOCK),)
	mlx5_core-y		+= lib/clock.o
endif

#
# Ipoib netdev
#
mlx5_core-$(CONFIG_MLX5_CORE_IPOIB) += ipoib/ipoib.o ipoib/ethtool.o ipoib/ipoib_vlan.o

#
# Accelerations & FPGA
#
mlx5_core-$(CONFIG_MLX5_ACCEL) += accel/ipsec.o accel/tls.o

mlx5_core-$(CONFIG_MLX5_FPGA) += fpga/cmd.o fpga/core.o fpga/conn.o fpga/sdk.o \
			fpga/ipsec.o fpga/tls.o fpga/trans.o fpga/xfer.o

mlx5_core-$(CONFIG_MLX5_EN_IPSEC) += en_accel/ipsec.o en_accel/ipsec_rxtx.o \
				     en_accel/ipsec_stats.o

mlx5_core-$(CONFIG_MLX5_EN_TLS) += en_accel/tls.o en_accel/tls_rxtx.o en_accel/tls_stats.o

#
# Mdev basic
#
mlx5_core-$(CONFIG_MLX5_MDEV) += meddev/sf.o meddev/mdev.o meddev/mdev_driver.o
