/*
 * Copyright (c) 2017 Mellanox Technologies Inc.  All rights reserved.
 * Copyright (c) 2010 Voltaire Inc.  All rights reserved.
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

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/export.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <rdma/rdma_netlink.h>
#include <linux/module.h>
#include "core_priv.h"

static DEFINE_MUTEX(rdma_nl_mutex);
static struct sock *nls;
static struct {
	const struct rdma_nl_cbs   *cb_table;
} rdma_nl_types[RDMA_NL_NUM_CLIENTS];

#if defined(HAVE_STRUCT_CLASS_NS_TYPE) && defined(HAVE_PERENT_OPERATIONS_ID)
bool rdma_nl_chk_listeners(unsigned int group)
{
	struct rdma_dev_net *rnet = rdma_net_to_dev_net(&init_net);

	return netlink_has_listeners(rnet->nl_sock, group);
}
#else
bool rdma_nl_chk_listeners(unsigned int group)
{
	return netlink_has_listeners(nls, group);
}
#endif
EXPORT_SYMBOL(rdma_nl_chk_listeners);

static bool is_nl_msg_valid(unsigned int type, unsigned int op)
{
	static const unsigned int max_num_ops[RDMA_NL_NUM_CLIENTS] = {
		[RDMA_NL_IWCM] = RDMA_NL_IWPM_NUM_OPS,
		[RDMA_NL_LS] = RDMA_NL_LS_NUM_OPS,
		[RDMA_NL_NLDEV] = RDMA_NLDEV_NUM_OPS,
	};

	/*
	 * This BUILD_BUG_ON is intended to catch addition of new
	 * RDMA netlink protocol without updating the array above.
	 */
	BUILD_BUG_ON(RDMA_NL_NUM_CLIENTS != 6);

	if (type >= RDMA_NL_NUM_CLIENTS)
		return false;

	return (op < max_num_ops[type]) ? true : false;
}

static bool
is_nl_valid(const struct sk_buff *skb, unsigned int type, unsigned int op)
{
	const struct rdma_nl_cbs *cb_table;

	if (!is_nl_msg_valid(type, op))
		return false;

	/*
	 * Currently only NLDEV client is supporting netlink commands in
	 * non init_net net namespace.
	 */
	if (sock_net(skb->sk) != &init_net && type != RDMA_NL_NLDEV)
		return false;

	if (!rdma_nl_types[type].cb_table) {
		mutex_unlock(&rdma_nl_mutex);
		request_module("rdma-netlink-subsys-%d", type);
		mutex_lock(&rdma_nl_mutex);
	}

	cb_table = rdma_nl_types[type].cb_table;

	if (!cb_table || (!cb_table[op].dump && !cb_table[op].doit))
		return false;

	return true;
}

void rdma_nl_register(unsigned int index,
		      const struct rdma_nl_cbs cb_table[])
{
	mutex_lock(&rdma_nl_mutex);
	if (!is_nl_msg_valid(index, 0)) {
		/*
		 * All clients are not interesting in success/failure of
		 * this call. They want to see the print to error log and
		 * continue their initialization. Print warning for them,
		 * because it is programmer's error to be here.
		 */
		mutex_unlock(&rdma_nl_mutex);
		WARN(true,
		     "The not-valid %u index was supplied to RDMA netlink\n",
		     index);
		return;
	}

	if (rdma_nl_types[index].cb_table) {
		mutex_unlock(&rdma_nl_mutex);
		WARN(true,
		     "The %u index is already registered in RDMA netlink\n",
		     index);
		return;
	}

	rdma_nl_types[index].cb_table = cb_table;
	mutex_unlock(&rdma_nl_mutex);
}
EXPORT_SYMBOL(rdma_nl_register);

void rdma_nl_unregister(unsigned int index)
{
	mutex_lock(&rdma_nl_mutex);
	rdma_nl_types[index].cb_table = NULL;
	mutex_unlock(&rdma_nl_mutex);
}
EXPORT_SYMBOL(rdma_nl_unregister);

void *ibnl_put_msg(struct sk_buff *skb, struct nlmsghdr **nlh, int seq,
		   int len, int client, int op, int flags)
{
	*nlh = nlmsg_put(skb, 0, seq, RDMA_NL_GET_TYPE(client, op), len, flags);
	if (!*nlh)
		return NULL;
	return nlmsg_data(*nlh);
}
EXPORT_SYMBOL(ibnl_put_msg);

int ibnl_put_attr(struct sk_buff *skb, struct nlmsghdr *nlh,
		  int len, void *data, int type)
{
	if (nla_put(skb, type, len, data)) {
		nlmsg_cancel(skb, nlh);
		return -EMSGSIZE;
	}
	return 0;
}
EXPORT_SYMBOL(ibnl_put_attr);

#ifdef HAVE_NETLINK_EXT_ACK
static int rdma_nl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
			   struct netlink_ext_ack *extack)
#else
static int rdma_nl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
#endif
{
	int type = nlh->nlmsg_type;
	unsigned int index = RDMA_NL_GET_CLIENT(type);
	unsigned int op = RDMA_NL_GET_OP(type);
	const struct rdma_nl_cbs *cb_table;

	if (!is_nl_valid(skb, index, op))
		return -EINVAL;

	cb_table = rdma_nl_types[index].cb_table;

	if ((cb_table[op].flags & RDMA_NL_ADMIN_PERM) &&
#ifdef HAVE_NETLINK_CAPABLE
	    !netlink_capable(skb, CAP_NET_ADMIN))
#else
	    sock_net(skb->sk) != &init_net)
#endif
		return -EPERM;

	/*
	 * LS responses overload the 0x100 (NLM_F_ROOT) flag.  Don't
	 * mistakenly call the .dump() function.
	 */
	if (index == RDMA_NL_LS) {
		if (cb_table[op].doit)
#ifdef HAVE_NETLINK_EXT_ACK
	     		return cb_table[op].doit(skb, nlh, extack);
#else
			return cb_table[op].doit(skb, nlh);
#endif
		return -EINVAL;
	}
	/* FIXME: Convert IWCM to properly handle doit callbacks */
	if ((nlh->nlmsg_flags & NLM_F_DUMP) || index == RDMA_NL_IWCM) {
#ifdef HAVE_NETLINK_DUMP_CONTROL_DUMP
		struct netlink_dump_control c = {
			.dump = cb_table[op].dump,
		};
		if (c.dump)
			return netlink_dump_start(skb->sk, skb, nlh, &c);
#else
		return netlink_dump_start(nls, skb, nlh,
					  cb_table[op].dump,
					  NULL, 0);
#endif
		return -EINVAL;
	}

	if (cb_table[op].doit)
#ifdef HAVE_NETLINK_EXT_ACK
		return cb_table[op].doit(skb, nlh, extack);
#else
		return cb_table[op].doit(skb, nlh);
#endif

	return 0;
}

/*
 * This function is similar to netlink_rcv_skb with one exception:
 * It calls to the callback for the netlink messages without NLM_F_REQUEST
 * flag. These messages are intended for RDMA_NL_LS consumer, so it is allowed
 * for that consumer only.
 */
static int rdma_nl_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *,
#ifdef HAVE_NETLINK_EXT_ACK
						   struct nlmsghdr *,
						   struct netlink_ext_ack *))
#else
						   struct nlmsghdr *))
#endif
{
#ifdef HAVE_NETLINK_EXT_ACK
	struct netlink_ext_ack extack = {};
#endif
	struct nlmsghdr *nlh;
	int err;

	while (skb->len >= nlmsg_total_size(0)) {
		int msglen;

		nlh = nlmsg_hdr(skb);
		err = 0;

		if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len)
			return 0;

		/*
		 * Generally speaking, the only requests are handled
		 * by the kernel, but RDMA_NL_LS is different, because it
		 * runs backward netlink scheme. Kernel initiates messages
		 * and waits for reply with data to keep pathrecord cache
		 * in sync.
		 */
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST) &&
		    (RDMA_NL_GET_CLIENT(nlh->nlmsg_type) != RDMA_NL_LS))
			goto ack;

		/* Skip control messages */
		if (nlh->nlmsg_type < NLMSG_MIN_TYPE)
			goto ack;

#ifdef HAVE_NETLINK_EXT_ACK
		err = cb(skb, nlh, &extack);
#else
		err = cb(skb, nlh);
#endif
		if (err == -EINTR)
			goto skip;

ack:
		if (nlh->nlmsg_flags & NLM_F_ACK || err)
#ifdef HAVE_NETLINK_EXT_ACK
			netlink_ack(skb, nlh, err, &extack);
#else
			netlink_ack(skb, nlh, err);
#endif

skip:
		msglen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msglen > skb->len)
			msglen = skb->len;
		skb_pull(skb, msglen);
	}

	return 0;
}

static void rdma_nl_rcv(struct sk_buff *skb)
{
	mutex_lock(&rdma_nl_mutex);
	rdma_nl_rcv_skb(skb, &rdma_nl_rcv_msg);
	mutex_unlock(&rdma_nl_mutex);
}

#if defined(HAVE_STRUCT_CLASS_NS_TYPE) && defined(HAVE_PERENT_OPERATIONS_ID)
int rdma_nl_unicast(struct net *net, struct sk_buff *skb, u32 pid)
{
	struct rdma_dev_net *rnet = rdma_net_to_dev_net(net);
	int err;

	err = netlink_unicast(rnet->nl_sock, skb, pid, MSG_DONTWAIT);
	return (err < 0) ? err : 0;
}
EXPORT_SYMBOL(rdma_nl_unicast);

int rdma_nl_unicast_wait(struct net *net, struct sk_buff *skb, __u32 pid)
{
	struct rdma_dev_net *rnet = rdma_net_to_dev_net(net);
	int err;

	err = netlink_unicast(rnet->nl_sock, skb, pid, 0);
	return (err < 0) ? err : 0;
}
EXPORT_SYMBOL(rdma_nl_unicast_wait);

int rdma_nl_multicast(struct net *net, struct sk_buff *skb,
		      unsigned int group, gfp_t flags)
{
	struct rdma_dev_net *rnet = rdma_net_to_dev_net(net);

	return nlmsg_multicast(rnet->nl_sock, skb, 0, group, flags);
}
EXPORT_SYMBOL(rdma_nl_multicast);

void rdma_nl_exit(void)
{
	int idx;

	for (idx = 0; idx < RDMA_NL_NUM_CLIENTS; idx++)
		WARN(rdma_nl_types[idx].cb_table,
		     "Nelink client %d wasn't released prior to unloading %s\n",
		     idx, KBUILD_MODNAME);
}

int rdma_nl_net_init(struct rdma_dev_net *rnet)
{
	struct net *net = read_pnet(&rnet->net);
#ifdef HAVE_NETLINK_KERNEL_CFG_INPUT
       struct netlink_kernel_cfg cfg = {
       	.input	= rdma_nl_rcv,
       };
       struct sock *nls;

#ifdef HAVE_NETLINK_KERNEL_CREATE_3_PARAMS
       nls = netlink_kernel_create(net, NETLINK_RDMA, &cfg);
#else
	nls = netlink_kernel_create(&init_net, NETLINK_RDMA, THIS_MODULE, &cfg);
#endif
#else /* HAVE_NETLINK_KERNEL_CFG_INPUT */
	nls = netlink_kernel_create(&init_net, NETLINK_RDMA, 0, rdma_nl_rcv,
				    NULL, THIS_MODULE);
#endif /* HAVE_NETLINK_KERNEL_CFG_INPUT */
	if (!nls)
		return -ENOMEM;

	nls->sk_sndtimeo = 10 * HZ;
	rnet->nl_sock = nls;
	return 0;
}

void rdma_nl_net_exit(struct rdma_dev_net *rnet)
{
	netlink_kernel_release(rnet->nl_sock);
}

#else

int rdma_nl_unicast(struct net *net, struct sk_buff *skb, u32 pid)
{
	int err;

	err = netlink_unicast(nls, skb, pid, MSG_DONTWAIT);
	return (err < 0) ? err : 0;
}
EXPORT_SYMBOL(rdma_nl_unicast);

int rdma_nl_unicast_wait(struct net *net, struct sk_buff *skb, __u32 pid)
{
	int err;

	err = netlink_unicast(nls, skb, pid, 0);
	return (err < 0) ? err : 0;
}
EXPORT_SYMBOL(rdma_nl_unicast_wait);

int rdma_nl_multicast(struct net *net, struct sk_buff *skb,
		      unsigned int group, gfp_t flags)
{
	return nlmsg_multicast(nls, skb, 0, group, flags);
}
EXPORT_SYMBOL(rdma_nl_multicast);

int __init rdma_nl_init(void)
{
#ifdef HAVE_NETLINK_KERNEL_CFG_INPUT
	struct netlink_kernel_cfg cfg = {
		.input	= rdma_nl_rcv,
	};

#ifdef HAVE_NETLINK_KERNEL_CREATE_3_PARAMS
       nls = netlink_kernel_create(&init_net, NETLINK_RDMA, &cfg);
#else
	nls = netlink_kernel_create(&init_net, NETLINK_RDMA, THIS_MODULE, &cfg);
#endif
#else /* HAVE_NETLINK_KERNEL_CFG_INPUT */
	nls = netlink_kernel_create(&init_net, NETLINK_RDMA, 0, rdma_nl_rcv,
				    NULL, THIS_MODULE);
#endif /* HAVE_NETLINK_KERNEL_CFG_INPUT */
	if (!nls)
		return -ENOMEM;

	nls->sk_sndtimeo = 10 * HZ;
	return 0;
}

void rdma_nl_exit(void)
{
	int idx;

	for (idx = 0; idx < RDMA_NL_NUM_CLIENTS; idx++)
		rdma_nl_unregister(idx);

	netlink_kernel_release(nls);
}
#endif

MODULE_ALIAS_NET_PF_PROTO(PF_NETLINK, NETLINK_RDMA);
