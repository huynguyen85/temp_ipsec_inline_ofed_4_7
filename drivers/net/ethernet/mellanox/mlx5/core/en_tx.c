/*
 * Copyright (c) 2015-2016, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include <net/geneve.h>
#include <net/dsfield.h>
#include "en.h"
#include "ipoib/ipoib.h"
#include "en_accel/en_accel.h"
#include "lib/clock.h"

#define MLX5E_SQ_NOPS_ROOM  MLX5_SEND_WQE_MAX_WQEBBS

#if defined(CONFIG_MLX5_EN_TLS) && defined(HAVE_UAPI_LINUX_TLS_H)
#define MLX5E_SQ_STOP_ROOM (MLX5_SEND_WQE_MAX_WQEBBS +\
			    MLX5E_SQ_NOPS_ROOM)
#else
/* TLS offload requires MLX5E_SQ_STOP_ROOM to have
 * enough room for a resync SKB, a normal SKB and a NOP
 */
#define MLX5E_SQ_STOP_ROOM (2 * MLX5_SEND_WQE_MAX_WQEBBS +\
			    MLX5E_SQ_NOPS_ROOM)
#endif

static inline void mlx5e_tx_dma_unmap(struct device *pdev,
				      struct mlx5e_sq_dma *dma)
{
	switch (dma->type) {
	case MLX5E_DMA_MAP_SINGLE:
		dma_unmap_single(pdev, dma->addr, dma->size, DMA_TO_DEVICE);
		break;
	case MLX5E_DMA_MAP_PAGE:
		dma_unmap_page(pdev, dma->addr, dma->size, DMA_TO_DEVICE);
		break;
	default:
		WARN_ONCE(true, "mlx5e_tx_dma_unmap unknown DMA type!\n");
	}
}

static inline struct mlx5e_sq_dma *mlx5e_dma_get(struct mlx5e_txqsq *sq, u32 i)
{
	return &sq->db.dma_fifo[i & sq->dma_fifo_mask];
}

static inline void mlx5e_dma_push(struct mlx5e_txqsq *sq,
				  dma_addr_t addr,
				  u32 size,
				  enum mlx5e_dma_map_type map_type)
{
	struct mlx5e_sq_dma *dma = mlx5e_dma_get(sq, sq->dma_fifo_pc++);

	dma->addr = addr;
	dma->size = size;
	dma->type = map_type;
}

static void mlx5e_dma_unmap_wqe_err(struct mlx5e_txqsq *sq, u8 num_dma)
{
	int i;

	for (i = 0; i < num_dma; i++) {
		struct mlx5e_sq_dma *last_pushed_dma =
			mlx5e_dma_get(sq, --sq->dma_fifo_pc);

		mlx5e_tx_dma_unmap(sq->pdev, last_pushed_dma);
	}
}

#ifdef HAVE_IEEE_DCBNL_ETS
#ifdef CONFIG_MLX5_CORE_EN_DCB
static inline int mlx5e_get_dscp_up(struct mlx5e_priv *priv, struct sk_buff *skb)
{
	int dscp_cp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp_cp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp_cp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return priv->dcbx_dp.dscp2prio[dscp_cp];
}
#endif
#endif

#if defined(CONFIG_MLX5_EN_SPECIAL_SQ) && (defined(HAVE_NDO_SET_TX_MAXRATE) || defined(HAVE_NDO_SET_TX_MAXRATE_EXTENDED))
static u16 mlx5e_select_queue_assigned(struct mlx5e_priv *priv,
				       struct sk_buff *skb)
{
	struct mlx5e_sq_flow_map *flow_map;
	int sk_ix = sk_tx_queue_get(skb->sk);
	u32 key_all, key_dip, key_dport;
	u16 dport;
	u32 dip;

	if (sk_ix >= priv->channels.params.num_channels)
		return sk_ix;

	if (vlan_get_protocol(skb) == htons(ETH_P_IP)) {
		dip = ip_hdr(skb)->daddr;
		if (ip_hdr(skb)->protocol == IPPROTO_UDP ||
		    ip_hdr(skb)->protocol == IPPROTO_TCP)
			dport = udp_hdr(skb)->dest;
		else
			goto fallback;
	} else {
		goto fallback;
	}

	key_all = dip ^ dport;
	hash_for_each_possible_rcu(priv->flow_map_hash, flow_map,
				   hlist, key_all)
		if (flow_map->dst_ip == dip && flow_map->dst_port == dport)
			return flow_map->queue_index;

	key_dip = dip;
	hash_for_each_possible_rcu(priv->flow_map_hash, flow_map,
				   hlist, key_dip)
		if (flow_map->dst_ip == dip)
			return flow_map->queue_index;

	key_dport = dport;
	hash_for_each_possible_rcu(priv->flow_map_hash, flow_map,
				   hlist, key_dport)
		if (flow_map->dst_port == dport)
			return flow_map->queue_index;

fallback:
	return 0;
}
#endif


#ifdef NDO_SELECT_QUEUE_HAS_3_PARMS_NO_FALLBACK
u16 mlx5e_select_queue(struct net_device *dev, struct sk_buff *skb,
		       struct net_device *sb_dev)

#elif defined(NDO_SELECT_QUEUE_HAS_ACCEL_PRIV) || defined(HAVE_SELECT_QUEUE_FALLBACK_T)

u16 mlx5e_select_queue(struct net_device *dev, struct sk_buff *skb,
#ifdef HAVE_SELECT_QUEUE_FALLBACK_T
#ifdef HAVE_SELECT_QUEUE_NET_DEVICE
		       struct net_device *sb_dev,
#else
		       void *accel_priv,
#endif /* HAVE_SELECT_QUEUE_NET_DEVICE */
		       select_queue_fallback_t fallback)
#else
		       void *accel_priv)
#endif
#else /* NDO_SELECT_QUEUE_HAS_ACCEL_PRIV || HAVE_SELECT_QUEUE_FALLBACK_T */
u16 mlx5e_select_queue(struct net_device *dev, struct sk_buff *skb)
#endif
{
	int txq_ix;
	struct mlx5e_priv *priv = netdev_priv(dev);
	u16 num_channels;
	int up;
#if defined(CONFIG_MLX5_EN_SPECIAL_SQ) && (defined(HAVE_NDO_SET_TX_MAXRATE) || defined(HAVE_NDO_SET_TX_MAXRATE_EXTENDED))
	if (priv->channels.params.num_rl_txqs) {
		u16 ix = mlx5e_select_queue_assigned(priv, skb);

		if (ix) {
			sk_tx_queue_set(skb->sk, ix);
			return ix;
		}
	}
#endif
#ifdef NDO_SELECT_QUEUE_HAS_3_PARMS_NO_FALLBACK
	txq_ix = netdev_pick_tx(dev, skb, NULL);
#elif defined (HAVE_SELECT_QUEUE_FALLBACK_T_3_PARAMS)
 	txq_ix = fallback(dev, skb, NULL);
#else
	txq_ix = fallback(dev, skb);
#endif
	up = 0;

#ifdef HAVE_NETDEV_GET_NUM_TC
	if (!netdev_get_num_tc(dev))
		return txq_ix;
#endif

#ifdef CONFIG_MLX5_CORE_EN_DCB
#ifdef HAVE_IEEE_DCBNL_ETS
	if (priv->dcbx_dp.trust_state == MLX5_QPTS_TRUST_DSCP)
		up = mlx5e_get_dscp_up(priv, skb);
	else
#endif
#endif
		if (skb_vlan_tag_present(skb))
			up = skb_vlan_tag_get_prio(skb);

	/* txq_ix can be larger than num_channels since
	 * dev->num_real_tx_queues = num_channels * num_tc
	 */
	num_channels = priv->channels.params.num_channels;
	if (txq_ix >= num_channels)
		txq_ix = priv->txq2sq[txq_ix]->ch_ix;

	return priv->channel_tc2txq[txq_ix][up];
}

static inline int mlx5e_skb_l2_header_offset(struct sk_buff *skb)
{
#define MLX5E_MIN_INLINE (ETH_HLEN + VLAN_HLEN)

	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	int l2_hlen = 0;

	if (unlikely(!__vlan_get_protocol(skb, eth->h_proto, &l2_hlen)))
		return max_t(int, skb_network_offset(skb), MLX5E_MIN_INLINE);

	return l2_hlen ? : ETH_HLEN;
}

static inline int mlx5e_skb_l3_header_offset(struct sk_buff *skb)
{
#ifdef HAVE_SKB_TRANSPORT_HEADER_WAS_SET
	if (skb_transport_header_was_set(skb))
#else
	if (skb->transport_header != (typeof(skb->transport_header))~0U)
#endif
		return skb_transport_offset(skb);
	else
		return mlx5e_skb_l2_header_offset(skb);
}

static inline u16 mlx5e_calc_min_inline(enum mlx5_inline_modes mode,
					struct sk_buff *skb,
					bool vlan_present)
{
	u16 hlen;

	switch (mode) {
	case MLX5_INLINE_MODE_NONE:
		return 0;
#ifdef HAVE_ETH_GET_HEADLEN
	case MLX5_INLINE_MODE_TCP_UDP:
#ifdef HAVE_ETH_GET_HEADLEN_3_PARAM
		hlen = eth_get_headlen(skb->dev, skb->data, skb_headlen(skb));
#else
		hlen = eth_get_headlen(skb->data, skb_headlen(skb));
#endif

		if (hlen == ETH_HLEN && !vlan_present)
			hlen += VLAN_HLEN;
		break;
#endif
	case MLX5_INLINE_MODE_IP:
		hlen = mlx5e_skb_l3_header_offset(skb);
		if (unlikely(hlen < ETH_HLEN + sizeof(struct iphdr)))
			hlen = MLX5E_MIN_INLINE + sizeof(struct ipv6hdr);
		break;
	case MLX5_INLINE_MODE_L2:
	default:
		hlen = mlx5e_skb_l2_header_offset(skb);
	}
	return min_t(u16, hlen, skb_headlen(skb));
}

static inline void mlx5e_insert_vlan(void *start, struct sk_buff *skb, u16 ihs)
{
	struct vlan_ethhdr *vhdr = (struct vlan_ethhdr *)start;
	int cpy1_sz = 2 * ETH_ALEN;
	int cpy2_sz = ihs - cpy1_sz;

	memcpy(vhdr, skb->data, cpy1_sz);
#ifdef HAVE_NETIF_F_HW_VLAN_STAG_RX
	vhdr->h_vlan_proto = skb->vlan_proto;
#else
	vhdr->h_vlan_proto = cpu_to_be16(ETH_P_8021Q);
#endif
	vhdr->h_vlan_TCI = cpu_to_be16(skb_vlan_tag_get(skb));
	memcpy(&vhdr->h_vlan_encapsulated_proto, skb->data + cpy1_sz, cpy2_sz);
}

static inline void
mlx5e_txwqe_build_eseg_csum(struct mlx5e_txqsq *sq, struct sk_buff *skb, struct mlx5_wqe_eth_seg *eseg)
{
	if (likely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM;
#ifdef HAVE_SK_BUFF_ENCAPSULATION
		if (skb->encapsulation) {
			eseg->cs_flags |= MLX5_ETH_WQE_L3_INNER_CSUM |
					  MLX5_ETH_WQE_L4_INNER_CSUM;
			sq->stats->csum_partial_inner++;
		} else {
			eseg->cs_flags |= MLX5_ETH_WQE_L4_CSUM;
			sq->stats->csum_partial++;
		}
#else
		eseg->cs_flags |= MLX5_ETH_WQE_L4_CSUM;
#endif
	} else
		sq->stats->csum_none++;
}

static inline u16
mlx5e_tx_get_gso_ihs(struct mlx5e_txqsq *sq, struct sk_buff *skb)
{
	struct mlx5e_sq_stats *stats = sq->stats;
	u16 ihs;

#if defined(HAVE_SKB_INNER_TRANSPORT_HEADER) && defined(HAVE_SK_BUFF_ENCAPSULATION)
	if (skb->encapsulation) {
#ifdef HAVE_SKB_INNER_TRANSPORT_OFFSET
		ihs = skb_inner_transport_offset(skb) + inner_tcp_hdrlen(skb);
#else
		ihs = skb_inner_transport_header(skb) - skb->data + inner_tcp_hdrlen(skb);
#endif
		stats->tso_inner_packets++;
		stats->tso_inner_bytes += skb->len - ihs;
	} else {
#endif
#ifdef HAVE_NETIF_F_GSO_UDP_L4 
		if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
			ihs = skb_transport_offset(skb) + sizeof(struct udphdr);
		else
#endif 
			ihs = skb_transport_offset(skb) + tcp_hdrlen(skb);
		stats->tso_packets++;
		stats->tso_bytes += skb->len - ihs;
#if defined(HAVE_SKB_INNER_TRANSPORT_HEADER) && defined(HAVE_SK_BUFF_ENCAPSULATION)
	}
#endif

	return ihs;
}

static inline int
mlx5e_txwqe_build_dsegs(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			unsigned char *skb_data, u16 headlen,
			struct mlx5_wqe_data_seg *dseg)
{
	dma_addr_t dma_addr = 0;
	u8 num_dma          = 0;
	int i;

	if (headlen) {
		dma_addr = dma_map_single(sq->pdev, skb_data, headlen,
					  DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(sq->pdev, dma_addr)))
			goto dma_unmap_wqe_err;

		dseg->addr       = cpu_to_be64(dma_addr);
		dseg->lkey       = sq->mkey_be;
		dseg->byte_count = cpu_to_be32(headlen);

		mlx5e_dma_push(sq, dma_addr, headlen, MLX5E_DMA_MAP_SINGLE);
		num_dma++;
		dseg++;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		struct skb_frag_struct *frag = &skb_shinfo(skb)->frags[i];
		int fsz = skb_frag_size(frag);

		dma_addr = skb_frag_dma_map(sq->pdev, frag, 0, fsz,
					    DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(sq->pdev, dma_addr)))
			goto dma_unmap_wqe_err;

		dseg->addr       = cpu_to_be64(dma_addr);
		dseg->lkey       = sq->mkey_be;
		dseg->byte_count = cpu_to_be32(fsz);

		mlx5e_dma_push(sq, dma_addr, fsz, MLX5E_DMA_MAP_PAGE);
		num_dma++;
		dseg++;
	}

	return num_dma;

dma_unmap_wqe_err:
	mlx5e_dma_unmap_wqe_err(sq, num_dma);
	return -ENOMEM;
}

static inline void mlx5e_fill_sq_frag_edge(struct mlx5e_txqsq *sq,
					   struct mlx5_wq_cyc *wq,
					   u16 pi, u16 nnops)
{
	struct mlx5e_tx_wqe_info *edge_wi, *wi = &sq->db.wqe_info[pi];

	edge_wi = wi + nnops;

	/* fill sq frag edge with nops to avoid wqe wrapping two pages */
	for (; wi < edge_wi; wi++) {
		wi->skb        = NULL;
		wi->num_wqebbs = 1;
		mlx5e_post_nop(wq, sq->sqn, &sq->pc);
	}
	sq->stats->nop += nnops;
}

static inline void
mlx5e_txwqe_complete(struct mlx5e_txqsq *sq, struct sk_buff *skb,
		     u8 opcode, u16 ds_cnt, u8 num_wqebbs, u32 num_bytes, u8 num_dma,
		     struct mlx5e_tx_wqe_info *wi, struct mlx5_wqe_ctrl_seg *cseg
#if defined(HAVE_SK_BUFF_XMIT_MORE) || defined(HAVE_NETDEV_XMIT_MORE)
		     ,bool xmit_more
#endif
		     )

{
	struct mlx5_wq_cyc *wq = &sq->wq;

	wi->num_bytes = num_bytes;
	wi->num_dma = num_dma;
	wi->num_wqebbs = num_wqebbs;
	wi->skb = skb;

	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | opcode);
	cseg->qpn_ds           = cpu_to_be32((sq->sqn << 8) | ds_cnt);

	netdev_tx_sent_queue(sq->txq, num_bytes);

#ifndef HAVE_SKB_SHARED_INFO_UNION_TX_FLAGS
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
#else
	if (unlikely(skb_shinfo(skb)->tx_flags.flags & SKBTX_HW_TSTAMP))
#endif
#ifndef HAVE_SKB_SHARED_INFO_UNION_TX_FLAGS
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
#else
		skb_shinfo(skb)->tx_flags.flags |= SKBTX_IN_PROGRESS;
#endif

	sq->pc += wi->num_wqebbs;
	if (unlikely(!mlx5e_wqc_has_room_for(wq, sq->cc, sq->pc, MLX5E_SQ_STOP_ROOM))) {
		netif_tx_stop_queue(sq->txq);
		sq->stats->stopped++;
	}

#if defined(HAVE_SK_BUFF_XMIT_MORE) || defined(HAVE_NETDEV_XMIT_MORE)
	if (!xmit_more || netif_xmit_stopped(sq->txq))
#endif
		mlx5e_notify_hw(wq, sq->pc, sq->uar_map, cseg);
}

#define INL_HDR_START_SZ (sizeof(((struct mlx5_wqe_eth_seg *)NULL)->inline_hdr.start))

netdev_tx_t mlx5e_sq_xmit(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			  struct mlx5e_tx_wqe *wqe, u16 pi
#if defined(HAVE_SK_BUFF_XMIT_MORE) || defined(HAVE_NETDEV_XMIT_MORE)
			  , bool xmit_more
#endif
			  )
{
	struct mlx5_wq_cyc *wq = &sq->wq;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_wqe_eth_seg  *eseg;
	struct mlx5_wqe_data_seg *dseg;
	struct mlx5e_tx_wqe_info *wi;

	bool vlan_present = skb_vlan_tag_present(skb);
	struct mlx5e_sq_stats *stats = sq->stats;
	u16 headlen, ihs, contig_wqebbs_room;
	u16 ds_cnt, ds_cnt_inl = 0;
	u8 num_wqebbs, opcode;
	u32 num_bytes;
	int num_dma;
	__be16 mss;

	/* Calc ihs and ds cnt, no writes to wqe yet */
	ds_cnt = sizeof(*wqe) / MLX5_SEND_WQE_DS;
	if (skb_is_gso(skb)) {
		opcode    = MLX5_OPCODE_LSO;
		mss       = cpu_to_be16(skb_shinfo(skb)->gso_size);
		ihs       = mlx5e_tx_get_gso_ihs(sq, skb);
		num_bytes = skb->len + (skb_shinfo(skb)->gso_segs - 1) * ihs;
		stats->packets += skb_shinfo(skb)->gso_segs;
	} else {
		opcode    = MLX5_OPCODE_SEND;
		mss       = 0;
		ihs = mlx5e_calc_min_inline(sq->min_inline_mode, skb,
					    vlan_present);
		num_bytes = max_t(unsigned int, skb->len, ETH_ZLEN);
		stats->packets++;
	}

	stats->bytes     += num_bytes;
#if defined(HAVE_SK_BUFF_XMIT_MORE) || defined(HAVE_NETDEV_XMIT_MORE)
	stats->xmit_more += xmit_more;
#endif

	headlen = skb->len - ihs - skb->data_len;
	ds_cnt += !!headlen;
	ds_cnt += skb_shinfo(skb)->nr_frags;

	if (ihs) {
		ihs += !!skb_vlan_tag_present(skb) * VLAN_HLEN;

		ds_cnt_inl = DIV_ROUND_UP(ihs - INL_HDR_START_SZ, MLX5_SEND_WQE_DS);
		ds_cnt += ds_cnt_inl;
	}

	num_wqebbs = DIV_ROUND_UP(ds_cnt, MLX5_SEND_WQEBB_NUM_DS);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);
	if (unlikely(contig_wqebbs_room < num_wqebbs)) {
#ifdef CONFIG_MLX5_EN_IPSEC
		struct mlx5_wqe_eth_seg cur_eth = wqe->eth;
#endif
		mlx5e_fill_sq_frag_edge(sq, wq, pi, contig_wqebbs_room);
		mlx5e_sq_fetch_wqe(sq, &wqe, &pi);
#ifdef CONFIG_MLX5_EN_IPSEC
		wqe->eth = cur_eth;
#endif
	}

	/* fill wqe */
	wi   = &sq->db.wqe_info[pi];
	cseg = &wqe->ctrl;
	eseg = &wqe->eth;
	dseg =  wqe->data;

#if IS_ENABLED(CONFIG_GENEVE)
	if (skb->encapsulation)
		mlx5e_tx_tunnel_accel(skb, eseg);
#endif
	mlx5e_txwqe_build_eseg_csum(sq, skb, eseg);

	eseg->mss = mss;

	if (ihs) {
		eseg->inline_hdr.sz = cpu_to_be16(ihs);
		if (vlan_present) {
			ihs -= VLAN_HLEN;
			mlx5e_insert_vlan(eseg->inline_hdr.start, skb, ihs);
			stats->added_vlan_packets++;
		} else {
			memcpy(eseg->inline_hdr.start, skb->data, ihs);
		}
		dseg += ds_cnt_inl;
	} else if (vlan_present) {
		eseg->insert.type = cpu_to_be16(MLX5_ETH_WQE_INSERT_VLAN);
#ifdef HAVE_NETIF_F_HW_VLAN_STAG_RX
		if (skb->vlan_proto == cpu_to_be16(ETH_P_8021AD))
			eseg->insert.type |= cpu_to_be16(MLX5_ETH_WQE_SVLAN);
#endif
		eseg->insert.vlan_tci = cpu_to_be16(skb_vlan_tag_get(skb));
		stats->added_vlan_packets++;
	}

	num_dma = mlx5e_txwqe_build_dsegs(sq, skb, skb->data + ihs, headlen, dseg);
	if (unlikely(num_dma < 0))
		goto err_drop;

	mlx5e_txwqe_complete(sq, skb, opcode, ds_cnt, num_wqebbs, num_bytes,
			     num_dma, wi, cseg
#if defined(HAVE_SK_BUFF_XMIT_MORE) || defined(HAVE_NETDEV_XMIT_MORE)
			    , xmit_more
#endif
			    );

	sq->dim_obj.sample.pkt_ctr  = sq->stats->packets;
	sq->dim_obj.sample.byte_ctr = sq->stats->bytes;


	return NETDEV_TX_OK;

err_drop:
	stats->dropped++;
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

netdev_tx_t mlx5e_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_tx_wqe *wqe;
	struct mlx5e_txqsq *sq;
	u16 pi;

	sq = priv->txq2sq[skb_get_queue_mapping(skb)];
	mlx5e_sq_fetch_wqe(sq, &wqe, &pi);

	/* might send skbs and update wqe and pi */
	skb = mlx5e_accel_handle_tx(skb, sq, dev, &wqe, &pi);
	if (unlikely(!skb))
		return NETDEV_TX_OK;

#ifdef HAVE_NETDEV_XMIT_MORE
	return mlx5e_sq_xmit(sq, skb, wqe, pi, netdev_xmit_more());
#elif defined(HAVE_SK_BUFF_XMIT_MORE)
	return mlx5e_sq_xmit(sq, skb, wqe, pi, skb->xmit_more);
#else
	return mlx5e_sq_xmit(sq, skb, wqe, pi);
#endif
}

static void mlx5e_dump_error_cqe(struct mlx5e_txqsq *sq,
				 struct mlx5_err_cqe *err_cqe)
{
	u32 ci = mlx5_cqwq_get_ci(&sq->cq.wq);

	netdev_err(sq->channel->netdev,
		   "Error cqe on cqn 0x%x, ci 0x%x, sqn 0x%x, opcode 0x%x, syndrome 0x%x, vendor syndrome 0x%x\n",
		   sq->cq.mcq.cqn, ci, sq->sqn,
		   get_cqe_opcode((struct mlx5_cqe64 *)err_cqe),
		   err_cqe->syndrome, err_cqe->vendor_err_synd);
	mlx5_dump_err_cqe(sq->cq.mdev, err_cqe);
}

bool mlx5e_poll_tx_cq(struct mlx5e_cq *cq, int napi_budget)
{
	struct mlx5e_sq_stats *stats;
	struct mlx5e_txqsq *sq;
	struct mlx5_cqe64 *cqe;
	u32 dma_fifo_cc;
	u32 nbytes;
	u16 npkts;
	u16 sqcc;
	int i;

	sq = container_of(cq, struct mlx5e_txqsq, cq);

	if (unlikely(!test_bit(MLX5E_SQ_STATE_ENABLED, &sq->state)))
		return false;

	cqe = mlx5_cqwq_get_cqe(&cq->wq);
	if (!cqe)
		return false;

	stats = sq->stats;

	npkts = 0;
	nbytes = 0;

	/* sq->cc must be updated only after mlx5_cqwq_update_db_record(),
	 * otherwise a cq overrun may occur
	 */
	sqcc = sq->cc;

	/* avoid dirtying sq cache line every cqe */
	dma_fifo_cc = sq->dma_fifo_cc;

	i = 0;
	do {
		u16 wqe_counter;
		bool last_wqe;

		mlx5_cqwq_pop(&cq->wq);

		wqe_counter = be16_to_cpu(cqe->wqe_counter);

		if (unlikely(get_cqe_opcode(cqe) == MLX5_CQE_REQ_ERR)) {
			if (!test_and_set_bit(MLX5E_SQ_STATE_RECOVERING,
					      &sq->state)) {
				mlx5e_dump_error_cqe(sq,
						     (struct mlx5_err_cqe *)cqe);
				queue_work(cq->channel->priv->wq,
					   &sq->recover_work);
			}
			stats->cqe_err++;
		}

		do {
			struct mlx5e_tx_wqe_info *wi;
			struct sk_buff *skb;
			u16 ci;
			int j;

			last_wqe = (sqcc == wqe_counter);

			ci = mlx5_wq_cyc_ctr2ix(&sq->wq, sqcc);
			wi = &sq->db.wqe_info[ci];
			skb = wi->skb;

			if (unlikely(!skb)) { /* nop */
				sqcc++;
				continue;
			}

#ifndef HAVE_SKB_SHARED_INFO_UNION_TX_FLAGS
			if (unlikely(skb_shinfo(skb)->tx_flags &
#else
			if (unlikely(skb_shinfo(skb)->tx_flags.flags &
#endif
				     SKBTX_HW_TSTAMP)) {
				struct skb_shared_hwtstamps hwts = {};

				hwts.hwtstamp =
					mlx5_timecounter_cyc2time(sq->clock,
								  get_cqe_ts(cqe));
				skb_tstamp_tx(skb, &hwts);
			}

			for (j = 0; j < wi->num_dma; j++) {
				struct mlx5e_sq_dma *dma =
					mlx5e_dma_get(sq, dma_fifo_cc++);

				mlx5e_tx_dma_unmap(sq->pdev, dma);
			}

			npkts++;
			nbytes += wi->num_bytes;
			sqcc += wi->num_wqebbs;
#ifdef HAVE_NAPI_CONSUME_SKB
			napi_consume_skb(skb, napi_budget);
#else
			dev_kfree_skb(skb);
#endif
		} while (!last_wqe);

	} while ((++i < MLX5E_TX_CQ_POLL_BUDGET) && (cqe = mlx5_cqwq_get_cqe(&cq->wq)));

	stats->cqes += i;

	mlx5_cqwq_update_db_record(&cq->wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	sq->dma_fifo_cc = dma_fifo_cc;
	sq->cc = sqcc;

	netdev_tx_completed_queue(sq->txq, npkts, nbytes);

	if (netif_tx_queue_stopped(sq->txq) &&
	    mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc,
				   MLX5E_SQ_STOP_ROOM) &&
	    !test_bit(MLX5E_SQ_STATE_RECOVERING, &sq->state)) {
		netif_tx_wake_queue(sq->txq);
		stats->wake++;
	}

	return (i == MLX5E_TX_CQ_POLL_BUDGET);
}

void mlx5e_free_txqsq_descs(struct mlx5e_txqsq *sq)
{
	struct mlx5e_tx_wqe_info *wi;
	struct sk_buff *skb;
	u16 ci;
	int i;

	while (sq->cc != sq->pc) {
		ci = mlx5_wq_cyc_ctr2ix(&sq->wq, sq->cc);
		wi = &sq->db.wqe_info[ci];
		skb = wi->skb;

		if (!skb) { /* nop */
			sq->cc++;
			continue;
		}

		for (i = 0; i < wi->num_dma; i++) {
			struct mlx5e_sq_dma *dma =
				mlx5e_dma_get(sq, sq->dma_fifo_cc++);

			mlx5e_tx_dma_unmap(sq->pdev, dma);
		}

		dev_kfree_skb_any(skb);
		sq->cc += wi->num_wqebbs;
	}
}

#ifdef CONFIG_MLX5_CORE_IPOIB
static inline void
mlx5i_txwqe_build_datagram(struct mlx5_av *av, u32 dqpn, u32 dqkey,
			   struct mlx5_wqe_datagram_seg *dseg)
{
	memcpy(&dseg->av, av, sizeof(struct mlx5_av));
	dseg->av.dqp_dct = cpu_to_be32(dqpn | MLX5_EXTENDED_UD_AV);
	dseg->av.key.qkey.qkey = cpu_to_be32(dqkey);
}

netdev_tx_t mlx5i_sq_xmit(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			  struct mlx5_av *av, u32 dqpn, u32 dqkey
#if defined(HAVE_SK_BUFF_XMIT_MORE) || defined(HAVE_NETDEV_XMIT_MORE)
			 , bool xmit_more
#endif
			 )
{
	struct mlx5_wq_cyc *wq = &sq->wq;
	struct mlx5i_tx_wqe *wqe;

	struct mlx5_wqe_datagram_seg *datagram;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_wqe_eth_seg  *eseg;
	struct mlx5_wqe_data_seg *dseg;
	struct mlx5e_tx_wqe_info *wi;

	bool vlan_present = skb_vlan_tag_present(skb);
	struct mlx5e_sq_stats *stats = sq->stats;
	u16 headlen, ihs, pi, contig_wqebbs_room;
	u16 ds_cnt, ds_cnt_inl = 0;
	u8 num_wqebbs, opcode;
	u32 num_bytes;
	int num_dma;
	__be16 mss;

	/* Calc ihs and ds cnt, no writes to wqe yet */
	ds_cnt = sizeof(*wqe) / MLX5_SEND_WQE_DS;
	if (skb_is_gso(skb)) {
		opcode    = MLX5_OPCODE_LSO;
		mss       = cpu_to_be16(skb_shinfo(skb)->gso_size);
		ihs       = mlx5e_tx_get_gso_ihs(sq, skb);
		num_bytes = skb->len + (skb_shinfo(skb)->gso_segs - 1) * ihs;
		stats->packets += skb_shinfo(skb)->gso_segs;
	} else {
		opcode    = MLX5_OPCODE_SEND;
		mss       = 0;
		ihs = mlx5e_calc_min_inline(sq->min_inline_mode, skb,
					    vlan_present);
		num_bytes = max_t(unsigned int, skb->len, ETH_ZLEN);
		stats->packets++;
	}

	stats->bytes     += num_bytes;
#if defined(HAVE_SK_BUFF_XMIT_MORE) || defined(HAVE_NETDEV_XMIT_MORE)
	stats->xmit_more += xmit_more;
#endif

	headlen = skb->len - ihs - skb->data_len;
	ds_cnt += !!headlen;
	ds_cnt += skb_shinfo(skb)->nr_frags;

	if (ihs) {
		ds_cnt_inl = DIV_ROUND_UP(ihs - INL_HDR_START_SZ, MLX5_SEND_WQE_DS);
		ds_cnt += ds_cnt_inl;
	}

	num_wqebbs = DIV_ROUND_UP(ds_cnt, MLX5_SEND_WQEBB_NUM_DS);
	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);
	if (unlikely(contig_wqebbs_room < num_wqebbs)) {
		mlx5e_fill_sq_frag_edge(sq, wq, pi, contig_wqebbs_room);
		pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	}

	mlx5i_sq_fetch_wqe(sq, &wqe, pi);

	/* fill wqe */
	wi       = &sq->db.wqe_info[pi];
	cseg     = &wqe->ctrl;
	datagram = &wqe->datagram;
	eseg     = &wqe->eth;
	dseg     =  wqe->data;

	mlx5i_txwqe_build_datagram(av, dqpn, dqkey, datagram);

	mlx5e_txwqe_build_eseg_csum(sq, skb, eseg);

	eseg->mss = mss;

	if (ihs) {
		memcpy(eseg->inline_hdr.start, skb->data, ihs);
		eseg->inline_hdr.sz = cpu_to_be16(ihs);
		dseg += ds_cnt_inl;
	}

	num_dma = mlx5e_txwqe_build_dsegs(sq, skb, skb->data + ihs, headlen, dseg);
	if (unlikely(num_dma < 0))
		goto err_drop;

	mlx5e_txwqe_complete(sq, skb, opcode, ds_cnt, num_wqebbs, num_bytes,
			     num_dma, wi, cseg
#if defined(HAVE_SK_BUFF_XMIT_MORE) || defined(HAVE_NETDEV_XMIT_MORE)
			    , xmit_more
#endif
			    );

	sq->dim_obj.sample.pkt_ctr  = sq->stats->packets;
	sq->dim_obj.sample.byte_ctr = sq->stats->bytes;


	return NETDEV_TX_OK;

err_drop:
	stats->dropped++;
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}
#endif
