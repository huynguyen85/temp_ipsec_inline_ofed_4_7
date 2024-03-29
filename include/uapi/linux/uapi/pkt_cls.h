#ifndef _COMPAT_UAPI_PKT_CLS_H
#define _COMPAT_UAPI_PKT_CLS_H 1

#if !defined(CONFIG_COMPAT_KERNEL_4_14)
#include "../../../../compat/config.h"

/*
 * Should we include linux/pkt_cls.h instead?
 */

#ifdef CONFIG_COMPAT_CLS_FLOWER_MOD

#ifndef CONFIG_NET_SCHED_NEW
/* Flower classifier */

enum {
	TCA_FLOWER_UNSPEC,
	TCA_FLOWER_CLASSID,
	TCA_FLOWER_INDEV,
	TCA_FLOWER_ACT,
	TCA_FLOWER_KEY_ETH_DST,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_DST_MASK,	/* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_SRC,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_SRC_MASK,	/* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_TYPE,	/* be16 */
	TCA_FLOWER_KEY_IP_PROTO,	/* u8 */
	TCA_FLOWER_KEY_IPV4_SRC,	/* be32 */
	TCA_FLOWER_KEY_IPV4_SRC_MASK,	/* be32 */
	TCA_FLOWER_KEY_IPV4_DST,	/* be32 */
	TCA_FLOWER_KEY_IPV4_DST_MASK,	/* be32 */
	TCA_FLOWER_KEY_IPV6_SRC,	/* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_SRC_MASK,	/* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_DST,	/* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_DST_MASK,	/* struct in6_addr */
	TCA_FLOWER_KEY_TCP_SRC,		/* be16 */
	TCA_FLOWER_KEY_TCP_DST,		/* be16 */
	TCA_FLOWER_KEY_UDP_SRC,		/* be16 */
	TCA_FLOWER_KEY_UDP_DST,		/* be16 */

	TCA_FLOWER_FLAGS,
	TCA_FLOWER_KEY_VLAN_ID,		/* be16 */
	TCA_FLOWER_KEY_VLAN_PRIO,	/* u8   */
	TCA_FLOWER_KEY_VLAN_ETH_TYPE,	/* be16 */

	TCA_FLOWER_KEY_ENC_KEY_ID,	/* be32 */
	TCA_FLOWER_KEY_ENC_IPV4_SRC,	/* be32 */
	TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,/* be32 */
	TCA_FLOWER_KEY_ENC_IPV4_DST,	/* be32 */
	TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,/* be32 */
	TCA_FLOWER_KEY_ENC_IPV6_SRC,	/* struct in6_addr */
	TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,/* struct in6_addr */
	TCA_FLOWER_KEY_ENC_IPV6_DST,	/* struct in6_addr */
	TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,/* struct in6_addr */

	TCA_FLOWER_KEY_TCP_SRC_MASK,	/* be16 */
	TCA_FLOWER_KEY_TCP_DST_MASK,	/* be16 */
	TCA_FLOWER_KEY_UDP_SRC_MASK,	/* be16 */
	TCA_FLOWER_KEY_UDP_DST_MASK,	/* be16 */
	TCA_FLOWER_KEY_SCTP_SRC_MASK,	/* be16 */
	TCA_FLOWER_KEY_SCTP_DST_MASK,	/* be16 */

	TCA_FLOWER_KEY_SCTP_SRC,	/* be16 */
	TCA_FLOWER_KEY_SCTP_DST,	/* be16 */

	TCA_FLOWER_KEY_ENC_UDP_SRC_PORT,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_DST_PORT,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK,	/* be16 */

	TCA_FLOWER_KEY_FLAGS,		/* be32 */
	TCA_FLOWER_KEY_FLAGS_MASK,	/* be32 */

	TCA_FLOWER_KEY_ICMPV4_CODE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV4_CODE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV4_TYPE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV6_CODE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV6_CODE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV6_TYPE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV6_TYPE_MASK,/* u8 */

	TCA_FLOWER_KEY_ARP_SIP,		/* be32 */
	TCA_FLOWER_KEY_ARP_SIP_MASK,	/* be32 */
	TCA_FLOWER_KEY_ARP_TIP,		/* be32 */
	TCA_FLOWER_KEY_ARP_TIP_MASK,	/* be32 */
	TCA_FLOWER_KEY_ARP_OP,		/* u8 */
	TCA_FLOWER_KEY_ARP_OP_MASK,	/* u8 */
	TCA_FLOWER_KEY_ARP_SHA,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_SHA_MASK,	/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_THA,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_THA_MASK,	/* ETH_ALEN */
};

#undef TCA_FLOWER_MAX
#define TCA_FLOWER_MAX TCA_FLOWER_KEY_ARP_THA_MASK

#ifndef HAVE_TCA_FLOWER_KEY_MPLS_TTL
enum {
	TCA_FLOWER_KEY_MPLS_TTL = TCA_FLOWER_MAX + 1,     /* u8 - 8 bits */
	TCA_FLOWER_KEY_MPLS_BOS,        /* u8 - 1 bit */
	TCA_FLOWER_KEY_MPLS_TC,         /* u8 - 3 bits */
	TCA_FLOWER_KEY_MPLS_LABEL,      /* be32 - 20 bits */

	TCA_FLOWER_KEY_TCP_FLAGS,       /* be16 */
	TCA_FLOWER_KEY_TCP_FLAGS_MASK,  /* be16 */

	TCA_FLOWER_KEY_IP_TOS,          /* u8 */
	TCA_FLOWER_KEY_IP_TOS_MASK,     /* u8 */
	TCA_FLOWER_KEY_IP_TTL,          /* u8 */
	TCA_FLOWER_KEY_IP_TTL_MASK,     /* u8 */
};

#undef TCA_FLOWER_MAX
#define TCA_FLOWER_MAX TCA_FLOWER_KEY_IP_TTL_MASK
#endif /* HAVE_TCA_FLOWER_KEY_MPLS_TTL */

#ifndef HAVE_TCA_FLOWER_KEY_CVLAN_ID
enum {
	TCA_FLOWER_KEY_CVLAN_ID = TCA_FLOWER_MAX + 1,	/* be16 */
	TCA_FLOWER_KEY_CVLAN_PRIO,	/* u8   */
	TCA_FLOWER_KEY_CVLAN_ETH_TYPE,	/* be16 */

	TCA_FLOWER_KEY_ENC_IP_TOS,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TOS_MASK,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TTL,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TTL_MASK,	/* u8 */
};

#undef TCA_FLOWER_MAX
#define TCA_FLOWER_MAX TCA_FLOWER_KEY_ENC_IP_TTL_MASK
#endif /* HAVE_TCA_FLOWER_KEY_CVLAN_ID */

/* tca flags definitions */
#define TCA_CLS_FLAGS_SKIP_HW	(1 << 0) /* don't offload filter to HW */
#define TCA_CLS_FLAGS_SKIP_SW	(1 << 1) /* don't use filter in SW */
#define TCA_CLS_FLAGS_IN_HW	(1 << 2) /* filter is offloaded to HW */

#else /* CONFIG_NET_SCHED_NEW */

#ifndef HAVE_TCA_FLOWER_KEY_SCTP_SRC_MASK
enum {
	TCA_FLOWER_KEY_SCTP_SRC_MASK = __TCA_FLOWER_MAX,	/* be16 */
	TCA_FLOWER_KEY_SCTP_DST_MASK,	/* be16 */

	TCA_FLOWER_KEY_SCTP_SRC,	/* be16 */
	TCA_FLOWER_KEY_SCTP_DST,	/* be16 */

	TCA_FLOWER_KEY_ENC_UDP_SRC_PORT,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_DST_PORT,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK,	/* be16 */

	TCA_FLOWER_KEY_FLAGS,		/* be32 */
	TCA_FLOWER_KEY_FLAGS_MASK,	/* be32 */

	TCA_FLOWER_KEY_ICMPV4_CODE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV4_CODE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV4_TYPE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV6_CODE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV6_CODE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV6_TYPE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV6_TYPE_MASK,/* u8 */

	TCA_FLOWER_KEY_ARP_SIP,		/* be32 */
	TCA_FLOWER_KEY_ARP_SIP_MASK,	/* be32 */
	TCA_FLOWER_KEY_ARP_TIP,		/* be32 */
	TCA_FLOWER_KEY_ARP_TIP_MASK,	/* be32 */
	TCA_FLOWER_KEY_ARP_OP,		/* u8 */
	TCA_FLOWER_KEY_ARP_OP_MASK,	/* u8 */
	TCA_FLOWER_KEY_ARP_SHA,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_SHA_MASK,	/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_THA,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_THA_MASK,	/* ETH_ALEN */
};

#undef TCA_FLOWER_MAX
#define TCA_FLOWER_MAX TCA_FLOWER_KEY_ARP_THA_MASK
#endif /* HAVE_TCA_FLOWER_KEY_SCTP_SRC_MASK */

#ifndef HAVE_TCA_FLOWER_KEY_MPLS_TTL
enum {
	TCA_FLOWER_KEY_MPLS_TTL = TCA_FLOWER_MAX + 1,     /* u8 - 8 bits */
	TCA_FLOWER_KEY_MPLS_BOS,        /* u8 - 1 bit */
	TCA_FLOWER_KEY_MPLS_TC,         /* u8 - 3 bits */
	TCA_FLOWER_KEY_MPLS_LABEL,      /* be32 - 20 bits */

	TCA_FLOWER_KEY_TCP_FLAGS,       /* be16 */
	TCA_FLOWER_KEY_TCP_FLAGS_MASK,  /* be16 */

	TCA_FLOWER_KEY_IP_TOS,          /* u8 */
	TCA_FLOWER_KEY_IP_TOS_MASK,     /* u8 */
	TCA_FLOWER_KEY_IP_TTL,          /* u8 */
	TCA_FLOWER_KEY_IP_TTL_MASK,     /* u8 */
};

#undef TCA_FLOWER_MAX
#define TCA_FLOWER_MAX TCA_FLOWER_KEY_IP_TTL_MASK
#endif /* HAVE_TCA_FLOWER_KEY_MPLS_TTL */

#ifndef HAVE_TCA_FLOWER_KEY_CVLAN_ID
enum {
	TCA_FLOWER_KEY_CVLAN_ID = TCA_FLOWER_MAX + 1,	/* be16 */
	TCA_FLOWER_KEY_CVLAN_PRIO,	/* u8   */
	TCA_FLOWER_KEY_CVLAN_ETH_TYPE,	/* be16 */

	TCA_FLOWER_KEY_ENC_IP_TOS,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TOS_MASK,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TTL,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TTL_MASK,	/* u8 */
};

#undef TCA_FLOWER_MAX
#define TCA_FLOWER_MAX TCA_FLOWER_KEY_ENC_IP_TTL_MASK
#endif /* HAVE_TCA_FLOWER_KEY_CVLAN_ID */

#endif /* CONFIG_NET_SCHED_NEW */

#ifndef TCA_CLS_FLAGS_IN_HW
#define TCA_CLS_FLAGS_IN_HW	(1 << 2) /* filter is offloaded to HW */
#endif

#ifndef TCA_CLS_FLAGS_NOT_IN_HW
#define TCA_CLS_FLAGS_NOT_IN_HW (1 << 3) /* filter isn't offloaded to HW */
#endif

#ifndef HAVE_TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT
enum {
	TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT = (1 << 0),
};
#endif

#ifndef HAVE_TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST
enum {
	TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST = (1 << 1),
};
#endif

#endif /* CONFIG_COMPAT_CLS_FLOWER_MOD */
#endif /* CONFIG_COMPAT_KERNEL_4_14 */
#endif /* _COMPAT_UAPI_PKT_CLS_H */
