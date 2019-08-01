/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2004 Voltaire, Inc. All rights reserved.
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

int ipoib_set_mode_rss(struct net_device *dev, const char *buf)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_send_ring *send_ring;
	int i;

	if ((test_bit(IPOIB_FLAG_ADMIN_CM, &priv->flags) &&
	     !strcmp(buf, "connected\n")) ||
	     (!test_bit(IPOIB_FLAG_ADMIN_CM, &priv->flags) &&
	     !strcmp(buf, "datagram\n"))) {
		ipoib_dbg(priv, "already in that mode, goes out.\n");
		return 0;
	}

	/* flush paths if we switch modes so that connections are restarted */
	if (IPOIB_CM_SUPPORTED(dev->dev_addr) && !strcmp(buf, "connected\n")) {
		set_bit(IPOIB_FLAG_ADMIN_CM, &priv->flags);
		ipoib_warn(priv, "enabling connected mode "
			   "will cause multicast packet drops\n");
		netdev_update_features(dev);
		dev_set_mtu(dev, ipoib_cm_max_mtu(dev));
		rtnl_unlock();

		send_ring = priv->send_ring;
		for (i = 0; i < priv->num_tx_queues; i++) {
			send_ring->tx_wr.wr.send_flags &= ~IB_SEND_IP_CSUM;
			send_ring++;
		}

		ipoib_flush_paths(dev);
		if (!rtnl_trylock())
			return -EBUSY;
		return 0;
	}

	if (!strcmp(buf, "datagram\n")) {
		clear_bit(IPOIB_FLAG_ADMIN_CM, &priv->flags);
		netdev_update_features(dev);
		dev_set_mtu(dev, min(priv->mcast_mtu, dev->mtu));
		rtnl_unlock();
		ipoib_flush_paths(dev);
		if (!rtnl_trylock())
			return -EBUSY;
		return 0;
	}

	return -EINVAL;
}

static u16 ipoib_select_queue_sw_rss(struct net_device *dev, struct sk_buff *skb,
				     void *accel_priv,
				     select_queue_fallback_t fallback)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_pseudo_header *phdr;
	struct ipoib_header *header;

	phdr = (struct ipoib_pseudo_header *) skb->data;

	/* (BC/MC) use designated QDISC -> parent QP */
	if (unlikely(phdr->hwaddr[4] == 0xff))
		return priv->tss_qp_num;

	/* is CM in use */
	if (IPOIB_CM_SUPPORTED(phdr->hwaddr)) {
		if (ipoib_cm_admin_enabled(dev)) {
			/* use remote QP for hash, so we use the same ring */
			u32 *daddr_32 = (u32 *) phdr->hwaddr;
			u32 hv = jhash_1word(*daddr_32 & 0xFFFFFF, 0);
			return hv % priv->tss_qp_num;
		}
		else
			/* the ADMIN CM might be up until transmit, and
			 * we might transmit on CM QP not from it's
			 * designated ring */
			phdr->hwaddr[0] &= ~IPOIB_FLAGS_RC;
	}

	/* Did neighbour advertise TSS support */
	if (unlikely(!IPOIB_TSS_SUPPORTED(phdr->hwaddr)))
		return priv->tss_qp_num;

	/* We are after ipoib_hard_header so skb->data is O.K. */
	header = (struct ipoib_header *) skb->data;
	header->tss_qpn_mask_sz |= priv->tss_qpn_mask_sz;

	/* don't use special ring in TX */
	return __skb_tx_hash(dev, skb, priv->tss_qp_num);
}

static void ipoib_timeout_rss(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_send_ring *send_ring;
	u16 index;

	ipoib_warn(priv, "transmit timeout: latency %d msecs\n",
		   jiffies_to_msecs(jiffies - dev_trans_start(dev)));

	for (index = 0; index < priv->num_tx_queues; index++) {
		if (__netif_subqueue_stopped(dev, index)) {
			send_ring = priv->send_ring + index;
			ipoib_warn(priv, "queue (%d) stopped, tx_head %u, tx_tail %u\n",
				   index,
				   send_ring->tx_head, send_ring->tx_tail);
		}
	}
	/* XXX reset QP, etc. */
}

static struct net_device_stats *ipoib_get_stats_rss(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	struct net_device_stats local_stats;
	int i;

	memset(&local_stats, 0, sizeof(struct net_device_stats));

	for (i = 0; i < priv->num_rx_queues; i++) {
		struct ipoib_rx_ring_stats *rstats = &priv->recv_ring[i].stats;
		local_stats.rx_packets += rstats->rx_packets;
		local_stats.rx_bytes   += rstats->rx_bytes;
		local_stats.rx_errors  += rstats->rx_errors;
		local_stats.rx_dropped += rstats->rx_dropped;
	}

	for (i = 0; i < priv->num_tx_queues; i++) {
		struct ipoib_tx_ring_stats *tstats = &priv->send_ring[i].stats;
		local_stats.tx_packets += tstats->tx_packets;
		local_stats.tx_bytes   += tstats->tx_bytes;
		local_stats.tx_errors  += tstats->tx_errors;
		local_stats.tx_dropped += tstats->tx_dropped;
	}

	stats->rx_packets = local_stats.rx_packets;
	stats->rx_bytes   = local_stats.rx_bytes;
	stats->rx_errors  = local_stats.rx_errors;
	stats->rx_dropped = local_stats.rx_dropped;

	stats->tx_packets = local_stats.tx_packets;
	stats->tx_bytes   = local_stats.tx_bytes;
	stats->tx_errors  = local_stats.tx_errors;
	stats->tx_dropped = local_stats.tx_dropped;

	return stats;
}

static struct ipoib_neigh *ipoib_neigh_ctor_rss(u8 *daddr,
						struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_neigh *neigh;

	neigh = kzalloc(sizeof *neigh, GFP_ATOMIC);
	if (!neigh)
		return NULL;

	neigh->dev = dev;
	memcpy(&neigh->daddr, daddr, sizeof(neigh->daddr));
	skb_queue_head_init(&neigh->queue);
	INIT_LIST_HEAD(&neigh->list);
	ipoib_cm_set(neigh, NULL);
	/* one ref on behalf of the caller */
	atomic_set(&neigh->refcnt, 1);

	/*
	 * ipoib_neigh_alloc can be called from neigh_add_path without
	 * the protection of spin lock or from ipoib_mcast_send under
	 * spin lock protection. thus there is a need to use atomic
	 */
	if (priv->tss_qp_num > 0)
		neigh->index = atomic_inc_return(&priv->tx_ring_ind)
			% priv->tss_qp_num;
	else
		neigh->index = 0;

	return neigh;
}

int ipoib_dev_init_rss(struct net_device *dev, struct ib_device *ca, int port)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_send_ring *send_ring;
	struct ipoib_recv_ring *recv_ring;
	int i, rx_allocated, tx_allocated;
	unsigned long alloc_size;

	/* Multi queue initialization */
	priv->recv_ring = kzalloc(priv->num_rx_queues * sizeof(*recv_ring),
				  GFP_KERNEL);

	if (!priv->recv_ring) {
		pr_warn("%s: failed to allocate RECV ring (%d entries)\n",
			ca->name, priv->num_rx_queues);
		goto out;
	}

	alloc_size = ipoib_recvq_size * sizeof(*recv_ring->rx_ring);
	rx_allocated = 0;
	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		recv_ring->rx_ring = kzalloc(alloc_size, GFP_KERNEL);
		if (!recv_ring->rx_ring) {
			pr_warn("%s: failed to allocate RX ring (%d entries)\n",
				ca->name, ipoib_recvq_size);
			goto out_recv_ring_cleanup;
		}
		recv_ring->dev = dev;
		recv_ring->index = i;
		recv_ring++;
		rx_allocated++;
	}

	priv->send_ring = kzalloc(priv->num_tx_queues * sizeof(*send_ring),
				  GFP_KERNEL);
	if (!priv->send_ring) {
		pr_warn("%s: failed to allocate SEND ring (%d entries)\n",
			ca->name, priv->num_tx_queues);
		goto out_recv_ring_cleanup;
	}

	alloc_size = ipoib_sendq_size * sizeof(*send_ring->tx_ring);
	tx_allocated = 0;
	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		send_ring->tx_ring = vzalloc(alloc_size);
		if (!send_ring->tx_ring) {
			pr_warn("%s: failed to allocate TX ring (%d entries)\n",
				ca->name, ipoib_sendq_size);
			goto out_send_ring_cleanup;
		}
		send_ring->dev = dev;
		send_ring->index = i;
		send_ring++;
		tx_allocated++;
	}

	/* priv->tx_head, tx_tail & tx_outstanding are already 0 */

	if (ipoib_ib_dev_init_rss(dev, ca, port))
		goto out_send_ring_cleanup;

	/*
	 * Must be after ipoib_ib_dev_init_rss so we can allocate a per
	 * device wq there and use it here
	 */
	if (ipoib_neigh_hash_init(priv) < 0)
		goto out_dev_uninit;

	return 0;

out_dev_uninit:
	ipoib_ib_dev_cleanup(dev);

out_send_ring_cleanup:
	for (i = 0; i < tx_allocated; i++)
		vfree(priv->send_ring[i].tx_ring);

out_recv_ring_cleanup:
	for (i = 0; i < rx_allocated; i++)
		kfree(priv->recv_ring[i].rx_ring);

out:
	priv->send_ring = NULL;
	priv->recv_ring = NULL;
	return -ENOMEM;
}

void ipoib_dev_cleanup_rss(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev), *cpriv, *tcpriv;
	int i;
	LIST_HEAD(head);

	ASSERT_RTNL();

	/* Delete any child interfaces first */
	list_for_each_entry_safe(cpriv, tcpriv, &priv->child_intfs, list) {
		/* Stop GC on child */
		set_bit(IPOIB_STOP_NEIGH_GC, &cpriv->flags);
		cancel_delayed_work(&cpriv->neigh_reap_task);
		unregister_netdevice_queue(cpriv->dev, &head);
	}
	unregister_netdevice_many(&head);

	/*
	 * Must be before ipoib_ib_dev_cleanup or we delete an in use
	 * work queue
	 */
	if (dev->reg_state != NETREG_UNINITIALIZED)
		ipoib_neigh_hash_uninit(dev);

	ipoib_ib_dev_cleanup(dev);

	for (i = 0; i < priv->num_tx_queues; i++)
		vfree(priv->send_ring[i].tx_ring);
	kfree(priv->send_ring);

	for (i = 0; i < priv->num_rx_queues; i++)
		kfree(priv->recv_ring[i].rx_ring);
	kfree(priv->recv_ring);

	priv->recv_ring = NULL;
	priv->send_ring = NULL;
}

static int ipoib_start_xmit_rss(struct sk_buff *skb, struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_neigh *neigh;
	struct ipoib_pseudo_header *phdr;
	struct ipoib_header *header;
	unsigned long flags;

	phdr = (struct ipoib_pseudo_header *) skb->data;
	skb_pull(skb, sizeof(*phdr));
	header = (struct ipoib_header *) skb->data;

	if (unlikely(phdr->hwaddr[4] == 0xff)) {
		/* multicast, arrange "if" according to probability */
		if ((header->proto != htons(ETH_P_IP)) &&
		    (header->proto != htons(ETH_P_IPV6)) &&
		    (header->proto != htons(ETH_P_ARP)) &&
		    (header->proto != htons(ETH_P_RARP)) &&
		    (header->proto != htons(ETH_P_TIPC))) {
			/* ethertype not supported by IPoIB */
			++dev->stats.tx_dropped;
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
		/* Add in the P_Key for multicast*/
		phdr->hwaddr[8] = (priv->pkey >> 8) & 0xff;
		phdr->hwaddr[9] = priv->pkey & 0xff;

		neigh = ipoib_neigh_get(dev, phdr->hwaddr);
		if (likely(neigh))
			goto send_using_neigh;
		ipoib_mcast_send(dev, phdr->hwaddr, skb);
		return NETDEV_TX_OK;
	}

	/* unicast, arrange "switch" according to probability */
	switch (header->proto) {
	case htons(ETH_P_IP):
	case htons(ETH_P_IPV6):
	case htons(ETH_P_TIPC):
		neigh = ipoib_neigh_get(dev, phdr->hwaddr);
		if (unlikely(!neigh)) {
			neigh_add_path(skb, phdr->hwaddr, dev);
			return NETDEV_TX_OK;
		}
		break;
	case htons(ETH_P_ARP):
	case htons(ETH_P_RARP):
		/* for unicast ARP and RARP should always perform path find */
		unicast_arp_send(skb, dev, phdr);
		return NETDEV_TX_OK;
	default:
		/* ethertype not supported by IPoIB */
		++dev->stats.tx_dropped;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

send_using_neigh:
	/* note we now hold a ref to neigh */
	if (ipoib_cm_get(neigh)) {
		if (ipoib_cm_up(neigh)) {
			ipoib_cm_send_rss(dev, skb, ipoib_cm_get(neigh));
			goto unref;
		}
	} else if (neigh->ah) {
		ipoib_send_rss(dev, skb, neigh->ah, IPOIB_QPN(phdr->hwaddr));
		goto unref;
	}

	if (skb_queue_len(&neigh->queue) < IPOIB_MAX_PATH_REC_QUEUE) {
		/* put pseudoheader back on for next time */
		skb_push(skb, sizeof(*phdr));
		spin_lock_irqsave(&priv->lock, flags);
		__skb_queue_tail(&neigh->queue, skb);
		spin_unlock_irqrestore(&priv->lock, flags);
	} else {
		++dev->stats.tx_dropped;
		dev_kfree_skb_any(skb);
	}

unref:
	ipoib_neigh_put(neigh);

	return NETDEV_TX_OK;
}

static int ipoib_get_hca_features(struct ipoib_dev_priv *priv,
				  struct ib_device *hca)
{
	int num_cores, result;
	struct ib_exp_device_attr exp_device_attr;
	struct ib_udata uhw = {.outlen = 0, .inlen = 0};

	result = ib_exp_query_device(hca, &exp_device_attr, &uhw);
	if (result) {
		ipoib_warn(priv, "%s: ib_exp_query_device failed (ret = %d)\n",
			   hca->name, result);
		return result;
	}

	priv->hca_caps = hca->attrs.device_cap_flags;
	priv->hca_caps_exp = exp_device_attr.device_cap_flags2;

	num_cores = num_online_cpus();
	if (num_cores == 1 || !(priv->hca_caps_exp & IB_EXP_DEVICE_QPG)) {
		/* No additional QP, only one QP for RX & TX */
		priv->rss_qp_num = 0;
		priv->tss_qp_num = 0;
		priv->num_rx_queues = 1;
		priv->num_tx_queues = 1;
		return 0;
	}
	num_cores = roundup_pow_of_two(num_cores);
	if (priv->hca_caps_exp & IB_EXP_DEVICE_UD_RSS) {
		int max_rss_tbl_sz;
		max_rss_tbl_sz = exp_device_attr.max_rss_tbl_sz;
		max_rss_tbl_sz = min(IPOIB_MAX_RX_QUEUES, max_rss_tbl_sz);
		max_rss_tbl_sz = min(num_cores, max_rss_tbl_sz);
		max_rss_tbl_sz = rounddown_pow_of_two(max_rss_tbl_sz);
		priv->rss_qp_num    = max_rss_tbl_sz;
		priv->num_rx_queues = max_rss_tbl_sz;
	} else {
		/* No additional QP, only the parent QP for RX */
		priv->rss_qp_num = 0;
		priv->num_rx_queues = 1;
	}

	priv->tss_qp_num = min(IPOIB_MAX_TX_QUEUES, num_cores);
	/* If TSS is not support by HW use the parent QP for ARP */
	priv->num_tx_queues = priv->tss_qp_num + 1;

	return 0;
}

static const struct net_device_ops ipoib_netdev_ops_pf_sw_tss = {
	.ndo_uninit		 = ipoib_uninit,
	.ndo_open		 = ipoib_open,
	.ndo_stop		 = ipoib_stop,
	.ndo_change_mtu		 = ipoib_change_mtu,
	.ndo_fix_features	 = ipoib_fix_features,
	.ndo_start_xmit		 = ipoib_start_xmit_rss,
	.ndo_select_queue	 = ipoib_select_queue_sw_rss,
	.ndo_tx_timeout		 = ipoib_timeout_rss,
	.ndo_get_stats		 = ipoib_get_stats_rss,
	.ndo_set_rx_mode	 = ipoib_set_mcast_list,
	.ndo_get_iflink		 = ipoib_get_iflink,
	.ndo_set_vf_link_state	 = ipoib_set_vf_link_state,
	.ndo_get_vf_config	 = ipoib_get_vf_config,
	.ndo_get_vf_stats	 = ipoib_get_vf_stats,
	.ndo_set_vf_guid	 = ipoib_set_vf_guid,
	.ndo_set_mac_address	 = ipoib_set_mac,
};

static const struct net_device_ops ipoib_netdev_ops_vf_sw_tss = {
	.ndo_uninit		 = ipoib_uninit,
	.ndo_open		 = ipoib_open,
	.ndo_stop		 = ipoib_stop,
	.ndo_change_mtu		 = ipoib_change_mtu,
	.ndo_fix_features	 = ipoib_fix_features,
	.ndo_start_xmit	 	 = ipoib_start_xmit_rss,
	.ndo_select_queue 	 = ipoib_select_queue_sw_rss,
	.ndo_tx_timeout		 = ipoib_timeout_rss,
	.ndo_get_stats		 = ipoib_get_stats_rss,
	.ndo_set_rx_mode	 = ipoib_set_mcast_list,
	.ndo_get_iflink		 = ipoib_get_iflink,
};

static const struct net_device_ops *ipoib_netdev_ops_select;

void ipoib_select_netdev_ops(struct ipoib_dev_priv *priv)
{
	if (priv->hca_caps & IB_DEVICE_VIRTUAL_FUNCTION)
		ipoib_netdev_ops_select = priv->num_tx_queues > 1 ?
			&ipoib_netdev_ops_vf_sw_tss : &ipoib_netdev_ops_vf;
	else
		ipoib_netdev_ops_select = priv->num_tx_queues > 1 ?
			&ipoib_netdev_ops_pf_sw_tss : &ipoib_netdev_ops_pf;
}

const struct net_device_ops *ipoib_get_netdev_ops(void)
{
	return ipoib_netdev_ops_select;
}

void ipoib_main_rss_init_fp(struct ipoib_dev_priv *priv)
{
	if (priv->hca_caps_exp & IB_EXP_DEVICE_UD_RSS) {
		priv->fp.ipoib_set_mode = ipoib_set_mode_rss;
		priv->fp.ipoib_neigh_ctor = ipoib_neigh_ctor_rss;
		priv->fp.ipoib_dev_init = ipoib_dev_init_rss;
		priv->fp.ipoib_dev_cleanup = ipoib_dev_cleanup_rss;
	} else {
		priv->fp.ipoib_set_mode = ipoib_set_mode;
		priv->fp.ipoib_neigh_ctor = ipoib_neigh_ctor;
		priv->fp.ipoib_dev_init = ipoib_dev_init;
		priv->fp.ipoib_dev_cleanup = ipoib_dev_cleanup;
	}
}
