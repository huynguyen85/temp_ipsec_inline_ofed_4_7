#ifndef COMPAT_NET_VXLAN_H
#define COMPAT_NET_VXLAN_H

#include "../../compat/config.h"

#include_next <net/vxlan.h>
#ifndef IANA_VXLAN_UDP_PORT 
#define IANA_VXLAN_UDP_PORT     4789
#endif

#ifndef HAVE_VXLAN_VNI_FIELD
static inline __be32 vxlan_vni_field(__be32 vni)
{
#if defined(__BIG_ENDIAN)
	return (__force __be32)((__force u32)vni << 8);
#else
	return (__force __be32)((__force u32)vni >> 8);
#endif
}
#endif

#undef VXLAN_HF_VNI
#define VXLAN_HF_VNI	cpu_to_be32(BIT(27))

#endif /* COMPAT_NET_VXLAN_H */

