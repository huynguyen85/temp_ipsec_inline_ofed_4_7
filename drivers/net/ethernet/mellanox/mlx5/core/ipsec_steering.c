/* Hello */

#include "ipsec_steering.h"

#define NUM_IPSEC_FTE BIT(15)
#define NUM_IPSEC_FG 1

struct mlx5_flow_table *err_t = NULL;
struct mlx5_flow_table *ipsec_t = NULL;
struct mlx5_flow_handle *copy_fte = NULL;
struct mlx5_flow_handle *ipsec_fte = NULL;
struct mlx5_flow_table *ipsec_tx_t = NULL;
struct mlx5_flow_handle *ipsec_rule = NULL;
u32 ipsec_obj_id = 0xABCD;
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

static int mlx5e_xfrm_add_rule(struct xfrm_state *x,
			       u32 ipsec_obj_id,
			       struct mlx5_flow_handle **rule)
{
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_handle *rule_tmp = NULL;
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_spec *spec = NULL;
	u16 ethertype;
	int err = 0;

	ethertype = x->props.family == AF_INET6 ? ETH_P_IPV6 : ETH_P_IP;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
			 outer_headers.ethertype);
	MLX5_SET(fte_match_param, spec->match_value, outer_headers.ethertype,
		 ethertype);

	if (ethertype == ETH_P_IP) {
		memcpy(MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    outer_headers.src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &x->props.saddr.a4,
		       4);
		memcpy(MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &x->id.daddr.a4,
		       4);
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
				 outer_headers.src_ipv4_src_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
				 outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	} else {
		memcpy(MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &x->props.saddr.a6,
		       16);
		memcpy(MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &x->id.daddr.a6,
		       16);
		memset(MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       0xff,
		       16);
		memset(MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       0xff,
		       16);
	}

	/* XFRM_OFFLOAD_INBOUND destination is error FT.
	 * Outbound action is ALLOW.
	 */
	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
		dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		dest.ft = err_t;
		rule_tmp = mlx5_add_flow_rules(ipsec_t, spec, &flow_act, &dest, 1);
	} else {
		flow_act.action = MLX5_FLOW_CONTEXT_ACTION_ALLOW;
		rule_tmp = mlx5_add_flow_rules(ipsec_tx_t, spec, &flow_act, NULL, 0);
	}

	if (IS_ERR(rule_tmp)) {
		err = PTR_ERR(rule_tmp);
		pr_err("Fail to add ipsec rule\n");
	} else {
		*rule = rule_tmp;
	}

out:
	kvfree(spec);
	return err;
}

static int mlx5e_xfrm_add_state(struct xfrm_state *x)
{
	pr_err("mlx5e_xfrm_add_state 001\n");
        pr_err("x->props.family=%x\n", x->props.family);
        pr_err("x->props.saddr.a4=%x\n", be32_to_cpu(x->props.saddr.a4));
        pr_err("x->id.daddr.a4=%x\n", be32_to_cpu(x->id.daddr.a4));
	pr_err("x->id.spi=%d\n", be32_to_cpu(x->id.spi));
	pr_err("x->xso.flags=%x\n", x->xso.flags);

	mlx5e_xfrm_add_rule(x, ipsec_obj_id, &ipsec_rule);

	return 0;
}

static void mlx5e_xfrm_del_state(struct xfrm_state *x)
{
	pr_err("mlx5e_xfrm_del_state 001\n");

	if (!IS_ERR_OR_NULL(ipsec_rule)) {
		mlx5_del_flow_rules(ipsec_rule);
		ipsec_rule = NULL;
	}
}

static bool mlx5e_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	
	pr_err("mlx5e_ipsec_offload_ok 001\n");
	if (x->props.family == AF_INET) {
		/* Offload with IPv4 options is not supported yet */
		if (ip_hdr(skb)->ihl > 5)
			return false;
	} else {
		/* Offload with IPv6 extension headers is not support yet */
		if (ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
	}

	return true;
}

static const struct xfrmdev_ops mlx5e_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add	= mlx5e_xfrm_add_state,
	.xdo_dev_state_delete	= mlx5e_xfrm_del_state,
	//.xdo_dev_state_free	= mlx5e_xfrm_free_state,
	.xdo_dev_offload_ok	= mlx5e_ipsec_offload_ok,
};

void quick_ipsec_ops(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;

	mlx5_core_info(priv->mdev, "Huy01 mlx5e: IPSec ESP acceleration enabled\n");
	netdev->xfrmdev_ops = &mlx5e_ipsec_xfrmdev_ops;
	netdev->features |= NETIF_F_HW_ESP;
	netdev->hw_enc_features |= NETIF_F_HW_ESP;
}
