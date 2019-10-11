/* Hello */

#include "ipsec_steering.h"

#define NUM_IPSEC_FTE BIT(15)
#define NUM_IPSEC_FG 1

struct mlx5_flow_table *err_t = NULL;
struct mlx5_flow_table *ipsec_t = NULL;
struct mlx5_flow_handle *copy_fte = NULL;
struct mlx5_flow_handle *ipsec_fte = NULL;
struct mlx5_flow_table *ipsec_tx_t = NULL;

u32 copy_modify_header_id = 0;

static int mlx5e_add_ipsec_copy_action_rule(struct mlx5_core_dev *mdev)
{
	u8 action[2][MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto)] = {};

	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec;
	int err = 0;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	/* Action to copy 8 bit ipsec_syndrome */
	MLX5_SET(copy_action_in, action[0], action_type, MLX5_ACTION_TYPE_COPY);
	MLX5_SET(copy_action_in, action[0], src_field, MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0); //To do
	MLX5_SET(copy_action_in, action[0], src_offset, 0);
	MLX5_SET(copy_action_in, action[0], length, 8);
	MLX5_SET(copy_action_in, action[0], dst_field, MLX5_ACTION_IN_FIELD_METADATA_REG_B);
	MLX5_SET(copy_action_in, action[0], dst_offset, 0);

	/* Action to copy 24 bit ipsec_obj_id */
	MLX5_SET(copy_action_in, action[1], action_type, MLX5_ACTION_TYPE_COPY);
	MLX5_SET(copy_action_in, action[1], src_field, MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0); //To do
	MLX5_SET(copy_action_in, action[1], src_offset, 0);
	MLX5_SET(copy_action_in, action[1], length, 24);
	MLX5_SET(copy_action_in, action[1], dst_field, MLX5_ACTION_IN_FIELD_METADATA_REG_B);
	MLX5_SET(copy_action_in, action[1], dst_offset, 8);

	err = mlx5_modify_header_alloc(mdev, MLX5_FLOW_NAMESPACE_ESW_INGRESS,
				       2, action, &copy_modify_header_id);

	if (err) {
		mlx5_core_err(mdev, "fail to alloc ipsec copy modify_header_id\n");
		goto out_spec;
	}

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_MOD_HDR | MLX5_FLOW_CONTEXT_ACTION_ALLOW;
	flow_act.modify_id = copy_modify_header_id;
	copy_fte = mlx5_add_flow_rules(err_t, spec, &flow_act, NULL, 0);
	if (IS_ERR(copy_fte)) {
		err = PTR_ERR(copy_fte);
		mlx5_core_err(mdev, "fail to add ipsec modify header rule err=%d\n", err);
		copy_fte = NULL;
		goto out;
	}

out:
	if (err)
		mlx5_modify_header_dealloc(mdev, copy_modify_header_id);
out_spec:
	kfree(spec);
	return err;
}

void mlx5e_del_ipsec_copy_action_rule(struct mlx5_core_dev *mdev)
{
        if (copy_fte) {
                mlx5_del_flow_rules(copy_fte);
                mlx5_modify_header_dealloc(mdev, copy_modify_header_id);
		copy_fte = NULL;
        }
}

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

	mlx5e_add_ipsec_copy_action_rule(mdev);
}

void mlx5e_ipsec_destroy_ft(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	
	mlx5_core_err(mdev, "001\n");
	mlx5e_del_ipsec_copy_action_rule(mdev);

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
