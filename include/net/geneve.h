/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _COMPAT__NET_GENEVE_H
#define _COMPAT__NET_GENEVE_H  1

#include "../../compat/config.h"

#include_next <net/geneve.h>

#ifndef GENEVE_UDP_PORT
#define GENEVE_UDP_PORT		6081
#endif

#endif /*ifdef_COMPAT__NET_GENEVE_H */
