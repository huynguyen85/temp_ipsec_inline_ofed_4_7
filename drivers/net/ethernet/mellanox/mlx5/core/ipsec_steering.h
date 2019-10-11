#include "en.h"
#include <linux/netdev_features.h>
#include <net/xfrm.h>

void mlx5e_ipsec_create_ft(struct mlx5e_priv *priv);
void mlx5e_ipsec_destroy_ft(struct mlx5e_priv *priv);

void quick_ipsec_ops(struct mlx5e_priv *priv);
