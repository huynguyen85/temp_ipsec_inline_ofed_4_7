# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_MLX5_INFINIBAND)	+= mlx5_ib.o

mlx5_ib-y :=	main.o cq.o doorbell.o qp.o mem.o srq_cmd.o \
		srq.o mr.o ah.o mad.o gsi.o ib_virt.o cmd.o \
		cong.o cq_exp.o qp_exp.o mr_exp.o main_exp.o srq_exp.o nvmf.o
mlx5_ib-$(CONFIG_INFINIBAND_ON_DEMAND_PAGING) += odp.o odp_exp.o
mlx5_ib-$(CONFIG_MLX5_ESWITCH) += ib_rep.o

ifneq ($(CONFIG_INFINIBAND_USER_ACCESS),)
	mlx5_ib-y += devx.o
	mlx5_ib-y += flow.o
endif
