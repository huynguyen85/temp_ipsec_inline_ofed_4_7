/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright (c) 2018 Mellanox Technologies. All rights reserved.
 */

#ifndef _MLX5_ESWITCH_
#define _MLX5_ESWITCH_

#include <linux/mlx5/driver.h>

#define MLX5_ESWITCH_MANAGER(mdev) MLX5_CAP_GEN(mdev, eswitch_manager)

enum {
	SRIOV_NONE,
	SRIOV_LEGACY,
	SRIOV_OFFLOADS
};

enum {
	REP_ETH,
	REP_IB,
	NUM_REP_TYPES,
};

enum {
	REP_UNREGISTERED,
	REP_REGISTERED,
	REP_LOADED,
};

struct mlx5_eswitch_rep;
struct mlx5_eswitch_rep_if {
	int		       (*load)(struct mlx5_core_dev *dev,
				       struct mlx5_eswitch_rep *rep);
	void		       (*unload)(struct mlx5_eswitch_rep *rep);
	void		       *(*get_proto_dev)(struct mlx5_eswitch_rep *rep);
	void			*priv;
	atomic_t		state;
};

struct mlx5_eswitch_rep {
	struct mlx5_eswitch_rep_if rep_if[NUM_REP_TYPES];
	u16		       vport;
	u8		       hw_id[ETH_ALEN];
	u16		       vlan;
	u32		       vlan_refcount;
};

void mlx5_eswitch_register_vport_reps(struct mlx5_eswitch *esw,
				      struct mlx5_eswitch_rep_if *rep_if,
				      u8 rep_type);
void mlx5_eswitch_unregister_vport_reps(struct mlx5_eswitch *esw, u8 rep_type);
void *mlx5_eswitch_get_proto_dev(struct mlx5_eswitch *esw,
				 u16 vport_num,
				 u8 rep_type);
struct mlx5_eswitch_rep *mlx5_eswitch_vport_rep(struct mlx5_eswitch *esw,
						u16 vport_num);
void *mlx5_eswitch_uplink_get_proto_dev(struct mlx5_eswitch *esw, u8 rep_type);
u8 mlx5_eswitch_mode(struct mlx5_eswitch *esw);
struct mlx5_flow_handle *
mlx5_eswitch_add_send_to_vport_rule(struct mlx5_eswitch *esw,
				    u16 vport_num, u32 sqn);

#ifdef CONFIG_MLX5_ESWITCH
u16 mlx5_eswitch_get_encap_mode(struct mlx5_eswitch *esw);
#else  /* CONFIG_MLX5_ESWITCH */
static inline u16 mlx5_eswitch_get_encap_mode(struct mlx5_eswitch *esw) { return 0; }
#endif /* CONFIG_MLX5_ESWITCH */

#endif
