/*
 * Copyright (c) 2015 Mellanox Technologies.  All rights reserved.
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

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_umem_odp.h>
#include <linux/sched.h>

#include <asm/uaccess.h>
#include <linux/sched.h>

#include "uverbs.h"
#include "core_priv.h"

int ib_uverbs_exp_create_qp(struct uverbs_attr_bundle *attrs)
{
	struct ib_uqp_object           *obj;
	struct ib_device	       *device;
	struct ib_device            *ib_dev;
	struct ib_pd                   *pd = NULL;
	struct ib_xrcd		       *xrcd = NULL;
	struct ib_uobject	       *xrcd_uobj = ERR_PTR(-ENOENT);
	struct ib_cq                   *scq = NULL, *rcq = NULL;
	struct ib_srq                  *srq = NULL;
	struct ib_qp                   *qp;
	struct ib_exp_qp_init_attr     *attr;
	struct ib_uverbs_exp_create_qp *cmd_exp;
	struct ib_uverbs_exp_create_qp_resp resp_exp;
	int                             ret;

	cmd_exp = kzalloc(sizeof(*cmd_exp), GFP_KERNEL);
	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!cmd_exp || !attr) {
		ret = -ENOMEM;
		goto err_cmd_attr;
	}

	ret = ib_copy_from_udata(cmd_exp, &attrs->ucore, sizeof(*cmd_exp));
	if (ret)
		goto err_cmd_attr;

	obj  = (struct ib_uqp_object *)uobj_alloc(UVERBS_OBJECT_QP,
						  attrs, &ib_dev);
	if (IS_ERR(obj))
		return PTR_ERR(obj);
	obj->uxrcd = NULL;
	obj->uevent.uobject.user_handle = cmd_exp->user_handle;


	if (cmd_exp->qp_type == IB_QPT_XRC_TGT) {
		xrcd_uobj = uobj_get_read(UVERBS_OBJECT_XRCD, cmd_exp->pd_handle,
					  attrs);

		if (IS_ERR(xrcd_uobj)) {
			ret = -EINVAL;
			goto err_put;
		}

		xrcd = (struct ib_xrcd *)xrcd_uobj->object;
		if (!xrcd) {
			ret = -EINVAL;
			goto err_put;
		}
		device = xrcd->device;
	} else {
		if (cmd_exp->qp_type == IB_QPT_XRC_INI) {
			cmd_exp->max_recv_wr = 0;
			cmd_exp->max_recv_sge = 0;
		} else {
			if (cmd_exp->is_srq) {
				srq = uobj_get_obj_read(srq, UVERBS_OBJECT_SRQ,
							cmd_exp->srq_handle,
							attrs);
				if (!srq || srq->srq_type != IB_SRQT_BASIC) {
					ret = -EINVAL;
					goto err_put;
				}
			}

			if (cmd_exp->recv_cq_handle != cmd_exp->send_cq_handle) {
				rcq = uobj_get_obj_read(cq, UVERBS_OBJECT_CQ,
							cmd_exp->recv_cq_handle,
							attrs);
				if (!rcq) {
					ret = -EINVAL;
					goto err_put;
				}
			}
		}

		scq = uobj_get_obj_read(cq, UVERBS_OBJECT_CQ,
					cmd_exp->send_cq_handle,
					attrs);
		rcq = rcq ?: scq;
		pd  = uobj_get_obj_read(pd, UVERBS_OBJECT_PD,
					cmd_exp->pd_handle, attrs);
		if (!pd || !scq) {
			ret = -EINVAL;
			goto err_put;
		}

		device = pd->device;
	}

	attr->event_handler = ib_uverbs_qp_event_handler;
	attr->qp_context    = attrs->ufile;
	attr->send_cq       = scq;
	attr->recv_cq       = rcq;
	attr->srq           = srq;
	attr->xrcd	   = xrcd;
	attr->sq_sig_type   = cmd_exp->sq_sig_all ? IB_SIGNAL_ALL_WR : IB_SIGNAL_REQ_WR;
	attr->qp_type       = cmd_exp->qp_type;
	attr->create_flags  = 0;

	attr->cap.max_send_wr     = cmd_exp->max_send_wr;
	attr->cap.max_recv_wr     = cmd_exp->max_recv_wr;
	attr->cap.max_send_sge    = cmd_exp->max_send_sge;
	attr->cap.max_recv_sge    = cmd_exp->max_recv_sge;
	attr->cap.max_inline_data = cmd_exp->max_inline_data;

	if (cmd_exp->comp_mask & IB_UVERBS_EXP_CREATE_QP_CAP_FLAGS) {
		if (cmd_exp->qp_cap_flags & ~IBV_UVERBS_EXP_CREATE_QP_FLAGS) {
			ret = -EINVAL;
			goto err_put;
		}
		attr->create_flags |= cmd_exp->qp_cap_flags;
	}

	obj->uevent.events_reported     = 0;
	INIT_LIST_HEAD(&obj->uevent.event_list);
	INIT_LIST_HEAD(&obj->mcast_list);

	if (cmd_exp->qp_type == IB_QPT_XRC_TGT)
		qp = ib_create_qp(pd, (struct ib_qp_init_attr *)attr);
	else
		qp = device->ops.exp_create_qp(pd, attr, &attrs->driver_udata);

	if (IS_ERR(qp)) {
		ret = PTR_ERR(qp);
		goto err_put;
	}

	if (cmd_exp->qp_type != IB_QPT_XRC_TGT) {
		ret = ib_create_qp_security(qp, device);
		if (ret)
			goto err_copy;

		qp->real_qp	  = qp;
		qp->device	  = device;
		qp->pd		  = pd;
		qp->send_cq	  = attr->send_cq;
		qp->recv_cq	  = attr->recv_cq;
		qp->srq		  = attr->srq;
		qp->event_handler = attr->event_handler;
		qp->qp_context	  = attr->qp_context;
		qp->qp_type	  = attr->qp_type;
		atomic_set(&qp->usecnt, 0);
		atomic_inc(&pd->usecnt);
		atomic_inc(&attr->send_cq->usecnt);
		if (attr->recv_cq)
			atomic_inc(&attr->recv_cq->usecnt);
		if (attr->srq)
			atomic_inc(&attr->srq->usecnt);
	}
	qp->uobject = &obj->uevent.uobject;

	obj->uevent.uobject.object = qp;

	memset(&resp_exp, 0, sizeof(resp_exp));
	resp_exp.qpn             = qp->qp_num;
	resp_exp.qp_handle       = obj->uevent.uobject.id;
	resp_exp.max_recv_sge    = attr->cap.max_recv_sge;
	resp_exp.max_send_sge    = attr->cap.max_send_sge;
	resp_exp.max_recv_wr     = attr->cap.max_recv_wr;
	resp_exp.max_send_wr     = attr->cap.max_send_wr;

	ret = ib_copy_to_udata(&attrs->ucore, &resp_exp, sizeof(resp_exp));
	if (ret)
		goto err_copy;

	if (xrcd) {
		obj->uxrcd = container_of(xrcd_uobj, struct ib_uxrcd_object, uobject);
		atomic_inc(&obj->uxrcd->refcnt);
		uobj_put_read(xrcd_uobj);
	}

	if (pd)
		uobj_put_obj_read(pd);
	if (scq)
		uobj_put_obj_read(scq);
	if (rcq && rcq != scq)
		uobj_put_obj_read(rcq);
	if (srq)
		uobj_put_obj_read(srq);


	kfree(attr);
	kfree(cmd_exp);

	return uobj_alloc_commit(&obj->uevent.uobject, 0);

err_copy:
	ib_destroy_qp(qp);

err_put:
	if (!IS_ERR(xrcd_uobj))
		uobj_put_read(xrcd_uobj);
	if (pd)
		uobj_put_obj_read(pd);
	if (scq)
		uobj_put_obj_read(scq);
	if (rcq && rcq != scq)
		uobj_put_obj_read(rcq);
	if (srq)
		uobj_put_obj_read(srq);

	uobj_alloc_abort(&obj->uevent.uobject, attrs);

err_cmd_attr:
	kfree(attr);
	kfree(cmd_exp);
	return ret;
}

