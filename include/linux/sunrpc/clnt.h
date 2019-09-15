/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/include/linux/sunrpc/clnt.h
 *
 *  Declarations for the high-level RPC client interface
 *
 *  Copyright (C) 1995, 1996, Olaf Kirch <okir@monad.swb.de>
 */

#ifndef _COMPACT_LINUX_SUNRPC_CLNT_H
#define _COMPACT_LINUX_SUNRPC_CLNT_H

#include "../../../compat/config.h"

#ifndef HAVE_TRACE_RPCRDMA_H
#include_next <linux/sunrpc/clnt.h>
#endif

static inline int rpc_reply_expected(struct rpc_task *task)
{
	return (task->tk_msg.rpc_proc != NULL) &&
		(task->tk_msg.rpc_proc->p_decode != NULL);
}

#endif /* _COMPACT_LINUX_SUNRPC_CLNT_H */
