/* Hello */

#include "ipsec_steering.h"

#define NUM_IPSEC_FTE BIT(15)
#define NUM_IPSEC_FG 1

struct mlx5_flow_table *err_t = NULL;
struct mlx5_flow_table *ipsec_t = NULL;
struct mlx5_flow_handle *err_fte = NULL;
struct mlx5_flow_handle *ipsec_fte = NULL;
struct mlx5_flow_table *ipsec_tx_t = NULL;

void mlx5e_ipsec_create_ft(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;

	mlx5_core_err(mdev, "001\n");
	if (IS_ERR_OR_NULL(ipsec_t)) {
		ipsec_t = mlx5_create_auto_grouped_flow_table(
							priv->fs.ns,
							MLX5E_IPSEC_PRIO,
							NUM_IPSEC_FTE,
							NUM_IPSEC_FG,
							MLX5E_IPSEC_FT_LEVEL, 0);
                if (IS_ERR(ipsec_t)) {
			mlx5_core_err(mdev, "fail to create ipsec ft\n");
		}
	}

	if (IS_ERR_OR_NULL(err_t)) {
		err_t = mlx5_create_auto_grouped_flow_table(
							priv->fs.ns,
							MLX5E_IPSEC_PRIO,
							NUM_IPSEC_FTE,
							NUM_IPSEC_FG,
							MLX5E_IPSEC_ERR_FT_LEVEL, 0);
                if (IS_ERR(err_t)) {
			mlx5_core_err(mdev, "fail to create ipsec error ft\n");
		}
	}

	if (IS_ERR_OR_NULL(ipsec_tx_t)) {
		ipsec_tx_t = mlx5_create_auto_grouped_flow_table(
							priv->fs.egress_ns,
							0,
							NUM_IPSEC_FTE,
							NUM_IPSEC_FG,
							0, 0);
                if (IS_ERR(ipsec_tx_t)) {
			mlx5_core_err(mdev, "fail to create ipsec transmit ft\n");
		}
	}

	//mlx5e_ipsec_create_rule(priv);
}

void mlx5e_ipsec_destroy_ft(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	
	mlx5_core_err(mdev, "001\n");
	//mlx5e_ipsec_del_rule(priv);

	if (!IS_ERR_OR_NULL(ipsec_tx_t)) {
		mlx5_destroy_flow_table(ipsec_tx_t);
		ipsec_tx_t = NULL;
	}

	if (!IS_ERR_OR_NULL(err_t)) {
		mlx5_destroy_flow_table(err_t);
		err_t = NULL;
	}

	if (!IS_ERR_OR_NULL(ipsec_t)) {
		mlx5_destroy_flow_table(ipsec_t);
		ipsec_t = NULL;
	}
}

