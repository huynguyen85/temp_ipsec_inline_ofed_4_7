/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

#include <linux/highmem.h>
#include "mlx5_ib.h"

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
static void copy_odp_exp_caps(struct ib_exp_odp_caps *exp_caps,
			      struct ib_odp_caps *caps)
{
	exp_caps->general_odp_caps = caps->general_caps;
	exp_caps->per_transport_caps.rc_odp_caps = caps->per_transport_caps.rc_odp_caps;
	exp_caps->per_transport_caps.uc_odp_caps = caps->per_transport_caps.uc_odp_caps;
	exp_caps->per_transport_caps.ud_odp_caps = caps->per_transport_caps.ud_odp_caps;
}
#endif

int mlx5_ib_exp_query_device(struct ib_device *ibdev,
			     struct ib_exp_device_attr *props,
			     struct ib_udata *uhw)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	int ret;

	ret = mlx5_ib_query_device(ibdev, &props->base, uhw);
	if (ret)
		return ret;

	props->exp_comp_mask = 0;
	props->device_cap_flags2 = 0;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_CAP_FLAGS2;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_ODP;
	props->device_cap_flags2 |= IB_EXP_DEVICE_ODP;
	copy_odp_exp_caps(&props->odp_caps, &to_mdev(ibdev)->odp_caps);
#endif
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_WITH_TIMESTAMP_MASK |
		IB_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK;

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_DC_REQ_RD;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_DC_RES_RD;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_MAX_DCT;
	if (MLX5_CAP_GEN(dev->mdev, dct)) {
		props->device_cap_flags2 |= IB_EXP_DEVICE_DC_TRANSPORT;
		props->dc_rd_req = 1 << MLX5_CAP_GEN(dev->mdev, log_max_ra_req_dc);
		props->dc_rd_res = 1 << MLX5_CAP_GEN(dev->mdev, log_max_ra_res_dc);
		props->max_dct = props->base.max_qp;
	} else {
		props->dc_rd_req = 0;
		props->dc_rd_res = 0;
		props->max_dct = 0;
	}
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_INLINE_RECV_SZ;
	if (MLX5_CAP_GEN(dev->mdev, sctr_data_cqe))
		props->inline_recv_sz = MLX5_MAX_INLINE_RECEIVE_SIZE;
	else
		props->inline_recv_sz = 0;

	return 0;
}

static void mlx5_ib_enable_dc_tracer(struct mlx5_ib_dev *dev)
{
	struct device *device = dev->ib_dev.dma_device;
	struct mlx5_dc_tracer *dct = &dev->dctr;
	int order;
	void *tmp;
	int size;
	int err;

	size = MLX5_CAP_GEN(dev->mdev, num_ports) * 4096;
	if (size <= PAGE_SIZE)
		order = 0;
	else
		order = 1;

	dct->pg = alloc_pages(GFP_KERNEL, order);
	if (!dct->pg) {
		mlx5_ib_err(dev, "failed to allocate %d pages\n", order);
		return;
	}

	tmp = kmap(dct->pg);
	if (!tmp) {
		mlx5_ib_err(dev, "failed to kmap one page\n");
		err = -ENOMEM;
		goto map_err;
	}

	memset(tmp, 0xff, size);
	kunmap(dct->pg);

	dct->size = size;
	dct->order = order;
	dct->dma = dma_map_page(device, dct->pg, 0, size, DMA_FROM_DEVICE);
	if (dma_mapping_error(device, dct->dma)) {
		mlx5_ib_err(dev, "dma mapping error\n");
		goto map_err;
	}

	err = mlx5_core_set_dc_cnak_trace(dev->mdev, 1, dct->dma);
	if (err) {
		mlx5_ib_warn(dev, "failed to enable DC tracer\n");
		goto cmd_err;
	}

	return;

cmd_err:
	dma_unmap_page(device, dct->dma, size, DMA_FROM_DEVICE);
map_err:
	__free_pages(dct->pg, dct->order);
	dct->pg = NULL;
}

static void mlx5_ib_disable_dc_tracer(struct mlx5_ib_dev *dev)
{
	struct device *device = dev->ib_dev.dma_device;
	struct mlx5_dc_tracer *dct = &dev->dctr;
	int err;

	if (!dct->pg)
		return;

	err = mlx5_core_set_dc_cnak_trace(dev->mdev, 0, dct->dma);
	if (err) {
		mlx5_ib_warn(dev, "failed to disable DC tracer\n");
		return;
	}

	dma_unmap_page(device, dct->dma, dct->size, DMA_FROM_DEVICE);
	__free_pages(dct->pg, dct->order);
	dct->pg = NULL;
}

int mlx5_ib_mmap_dc_info_page(struct mlx5_ib_dev *dev,
			      struct vm_area_struct *vma)
{
	struct mlx5_dc_tracer *dct;
	phys_addr_t pfn;
	int err;

	if ((MLX5_CAP_GEN(dev->mdev, port_type) !=
	     MLX5_CAP_PORT_TYPE_IB) ||
	    (!mlx5_core_is_pf(dev->mdev)) ||
	    (!MLX5_CAP_GEN(dev->mdev, dc_cnak_trace)))
		return -ENOTSUPP;

	dct = &dev->dctr;
	if (!dct->pg) {
		mlx5_ib_err(dev, "mlx5_ib_mmap DC no page\n");
		return -ENOMEM;
	}

	pfn = page_to_pfn(dct->pg);
	err = remap_pfn_range(vma, vma->vm_start, pfn, dct->size, vma->vm_page_prot);
	if (err) {
		mlx5_ib_err(dev, "mlx5_ib_mmap DC remap_pfn_range failed\n");
		return err;
	}
	return 0;
}


enum {
	MLX5_DC_CNAK_SIZE		= 128,
	MLX5_NUM_BUF_IN_PAGE		= PAGE_SIZE / MLX5_DC_CNAK_SIZE,
	MLX5_CNAK_TX_CQ_SIGNAL_FACTOR	= 128,
	MLX5_DC_CNAK_SL			= 0,
	MLX5_DC_CNAK_VL			= 0,
};

static void dump_buf(void *buf, int size)
{
	__be32 *p = buf;
	int offset;
	int i;

	for (i = 0, offset = 0; i < size; i += 16) {
		pr_info("%03x: %08x %08x %08x %08x\n", offset, be32_to_cpu(p[0]),
			be32_to_cpu(p[1]), be32_to_cpu(p[2]), be32_to_cpu(p[3]));
		p += 4;
		offset += 16;
	}
	pr_info("\n");
}

enum {
	CNAK_LENGTH_WITHOUT_GRH	= 32,
	CNAK_LENGTH_WITH_GRH	= 72,
};

static struct mlx5_dc_desc *get_desc_from_index(struct mlx5_dc_desc *desc, u64 index, unsigned *offset)
{
	struct mlx5_dc_desc *d;

	int i;
	int j;

	i = index / MLX5_NUM_BUF_IN_PAGE;
	j = index % MLX5_NUM_BUF_IN_PAGE;
	d = desc + i;
	*offset = j * MLX5_DC_CNAK_SIZE;
	return d;
}

static void build_cnak_msg(void *rbuf, void *sbuf, u32 *length, u16 *dlid)
{
	void *rdceth, *sdceth;
	void *rlrh, *slrh;
	void *rgrh, *sgrh;
	void *rbth, *sbth;
	int is_global;
	void *saeth;

	memset(sbuf, 0, MLX5_DC_CNAK_SIZE);
	rlrh = rbuf;
	is_global = MLX5_GET(lrh, rlrh, lnh) == 0x3;
	rgrh = is_global ? rlrh + MLX5_ST_SZ_BYTES(lrh) : NULL;
	rbth = rgrh ? rgrh + MLX5_ST_SZ_BYTES(grh) : rlrh + MLX5_ST_SZ_BYTES(lrh);
	rdceth = rbth + MLX5_ST_SZ_BYTES(bth);

	slrh = sbuf;
	sgrh = is_global ? slrh + MLX5_ST_SZ_BYTES(lrh) : NULL;
	sbth = sgrh ? sgrh + MLX5_ST_SZ_BYTES(grh) : slrh + MLX5_ST_SZ_BYTES(lrh);
	sdceth = sbth + MLX5_ST_SZ_BYTES(bth);
	saeth = sdceth + MLX5_ST_SZ_BYTES(dceth);

	*dlid = MLX5_GET(lrh, rlrh, slid);
	MLX5_SET(lrh, slrh, vl, MLX5_DC_CNAK_VL);
	MLX5_SET(lrh, slrh, lver, MLX5_GET(lrh, rlrh, lver));
	MLX5_SET(lrh, slrh, sl, MLX5_DC_CNAK_SL);
	MLX5_SET(lrh, slrh, lnh, MLX5_GET(lrh, rlrh, lnh));
	MLX5_SET(lrh, slrh, dlid, MLX5_GET(lrh, rlrh, slid));
	MLX5_SET(lrh, slrh, pkt_len, 0x9 + ((is_global ? MLX5_ST_SZ_BYTES(grh) : 0) >> 2));
	MLX5_SET(lrh, slrh, slid, MLX5_GET(lrh, rlrh, dlid));

	if (is_global) {
		void *rdgid, *rsgid;
		void *ssgid, *sdgid;

		MLX5_SET(grh, sgrh, ip_version, MLX5_GET(grh, rgrh, ip_version));
		MLX5_SET(grh, sgrh, traffic_class, MLX5_GET(grh, rgrh, traffic_class));
		MLX5_SET(grh, sgrh, flow_label, MLX5_GET(grh, rgrh, flow_label));
		MLX5_SET(grh, sgrh, payload_length, 0x1c);
		MLX5_SET(grh, sgrh, next_header, 0x1b);
		MLX5_SET(grh, sgrh, hop_limit, MLX5_GET(grh, rgrh, hop_limit));

		rdgid = MLX5_ADDR_OF(grh, rgrh, dgid);
		rsgid = MLX5_ADDR_OF(grh, rgrh, sgid);
		ssgid = MLX5_ADDR_OF(grh, sgrh, sgid);
		sdgid = MLX5_ADDR_OF(grh, sgrh, dgid);
		memcpy(ssgid, rdgid, 16);
		memcpy(sdgid, rsgid, 16);
		*length = CNAK_LENGTH_WITH_GRH;
	} else {
		*length = CNAK_LENGTH_WITHOUT_GRH;
	}

	MLX5_SET(bth, sbth, opcode, 0x51);
	MLX5_SET(bth, sbth, migreq, 0x1);
	MLX5_SET(bth, sbth, p_key, MLX5_GET(bth, rbth, p_key));
	MLX5_SET(bth, sbth, dest_qp, MLX5_GET(dceth, rdceth, dci_dct));
	MLX5_SET(bth, sbth, psn, MLX5_GET(bth, rbth, psn));

	MLX5_SET(dceth, sdceth, dci_dct, MLX5_GET(bth, rbth, dest_qp));

	MLX5_SET(aeth, saeth, syndrome, 0x64);

	if (0) {
		pr_info("===dump packet ====\n");
		dump_buf(sbuf, *length);
	}
}

static int reduce_tx_pending(struct mlx5_dc_data *dcd, int num)
{
	struct mlx5_ib_dev *dev = dcd->dev;
	struct ib_cq *cq = dcd->scq;
	unsigned int send_completed;
	unsigned int polled;
	struct ib_wc wc;
	int n;

	while (num > 0) {
		n = ib_poll_cq(cq, 1, &wc);
		if (unlikely(n < 0)) {
			mlx5_ib_warn(dev, "error polling cnak send cq\n");
			return n;
		}
		if (unlikely(!n))
			return -EAGAIN;

		if (unlikely(wc.status != IB_WC_SUCCESS)) {
			mlx5_ib_warn(dev, "cnak send completed with error, status %d vendor_err %d\n",
				     wc.status, wc.vendor_err);
			dcd->last_send_completed++;
			dcd->tx_pending--;
			num--;
		} else {
			send_completed = wc.wr_id;
			polled = send_completed - dcd->last_send_completed;
			dcd->tx_pending = (unsigned int)(dcd->cur_send - send_completed);
			num -= polled;
			dcd->cnaks += polled;
			dcd->last_send_completed = send_completed;
		}
	}

	return 0;
}

static int send_cnak(struct mlx5_dc_data *dcd, struct mlx5_send_wr *mlx_wr,
		     u64 rcv_buff_id)
{
	struct ib_send_wr *wr = &mlx_wr->wr;
	struct mlx5_ib_dev *dev = dcd->dev;
	const struct ib_send_wr *bad_wr;
	struct mlx5_dc_desc *rxd;
	struct mlx5_dc_desc *txd;
	unsigned int offset;
	unsigned int cur;
	__be32 *sbuf;
	void *rbuf;
	int err;

	if (unlikely(dcd->tx_pending > dcd->max_wqes)) {
		mlx5_ib_warn(dev, "SW error in cnak send: tx_pending(%d) > max_wqes(%d)\n",
			     dcd->tx_pending, dcd->max_wqes);
		return -EFAULT;
	}

	if (unlikely(dcd->tx_pending == dcd->max_wqes)) {
		err = reduce_tx_pending(dcd, 1);
		if (err)
			return err;
		if (dcd->tx_pending == dcd->max_wqes)
			return -EAGAIN;
	}

	cur = dcd->cur_send;
	txd = get_desc_from_index(dcd->txdesc, cur % dcd->max_wqes, &offset);
	sbuf = txd->buf + offset;

	wr->sg_list[0].addr = txd->dma + offset;
	wr->sg_list[0].lkey = dcd->mr->lkey;
	wr->opcode = IB_WR_SEND;
	wr->num_sge = 1;
	wr->wr_id = cur;
	if (cur % MLX5_CNAK_TX_CQ_SIGNAL_FACTOR)
		wr->send_flags &= ~IB_SEND_SIGNALED;
	else
		wr->send_flags |= IB_SEND_SIGNALED;

	rxd = get_desc_from_index(dcd->rxdesc, rcv_buff_id, &offset);
	rbuf = rxd->buf + offset;
	build_cnak_msg(rbuf, sbuf, &wr->sg_list[0].length, &mlx_wr->sel.mlx.dlid);

	mlx_wr->sel.mlx.sl = MLX5_DC_CNAK_SL;
	mlx_wr->sel.mlx.icrc = 1;

	err = ib_post_send(dcd->dcqp, wr, &bad_wr);
	if (likely(!err)) {
		dcd->tx_pending++;
		dcd->cur_send++;
	}

	return err;
}

static int mlx5_post_one_rxdc(struct mlx5_dc_data *dcd, int index)
{
	const struct ib_recv_wr *bad_wr;
	struct ib_recv_wr wr;
	struct ib_sge sge;
	u64 addr;
	int err;
	int i;
	int j;

	i = index / (PAGE_SIZE / MLX5_DC_CNAK_SIZE);
	j = index % (PAGE_SIZE / MLX5_DC_CNAK_SIZE);
	addr = dcd->rxdesc[i].dma + j * MLX5_DC_CNAK_SIZE;

	memset(&wr, 0, sizeof(wr));
	wr.num_sge = 1;
	sge.addr = addr;
	sge.length = MLX5_DC_CNAK_SIZE;
	sge.lkey = dcd->mr->lkey;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr_id = index;
	err = ib_post_recv(dcd->dcqp, &wr, &bad_wr);
	if (unlikely(err))
		mlx5_ib_warn(dcd->dev, "failed to post dc rx buf at index %d\n", index);

	return err;
}

static void dc_cnack_rcv_comp_handler(struct ib_cq *cq, void *cq_context)
{
	struct mlx5_dc_data *dcd = cq_context;
	struct mlx5_ib_dev *dev = dcd->dev;
	struct mlx5_send_wr mlx_wr;
	struct ib_send_wr *wr = &mlx_wr.wr;
	struct ib_wc *wc = dcd->wc_tbl;
	struct ib_sge sge;
	int err;
	int n;
	int i;

	memset(&mlx_wr, 0, sizeof(mlx_wr));
	wr->sg_list = &sge;

	n = ib_poll_cq(cq, MLX5_CNAK_RX_POLL_CQ_QUOTA, wc);
	if (unlikely(n < 0)) {
		/* mlx5 never returns negative values but leave a message just in case */
		mlx5_ib_warn(dev, "failed to poll cq (%d), aborting\n", n);
		return;
	}
	if (likely(n > 0)) {
		for (i = 0; i < n; i++) {
			if (dev->mdev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR)
				return;

			if (unlikely(wc[i].status != IB_WC_SUCCESS)) {
				mlx5_ib_warn(dev, "DC cnak: completed with error, status = %d vendor_err = %d\n",
					     wc[i].status, wc[i].vendor_err);
			} else {
				dcd->connects++;
				if (unlikely(send_cnak(dcd, &mlx_wr, wc[i].wr_id)))
					mlx5_ib_warn(dev, "DC cnak: failed to allocate send buf - dropped\n");
			}

			if (unlikely(mlx5_post_one_rxdc(dcd, wc[i].wr_id))) {
				dcd->discards++;
				mlx5_ib_warn(dev, "DC cnak: repost rx failed, will leak rx queue\n");
			}
		}
	}

	err = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (unlikely(err))
		mlx5_ib_warn(dev, "DC cnak: failed to re-arm receive cq (%d)\n", err);
}

static int alloc_dc_buf(struct mlx5_dc_data *dcd, int rx)
{
	struct mlx5_ib_dev *dev = dcd->dev;
	struct mlx5_dc_desc **desc;
	struct mlx5_dc_desc *d;
	struct device *ddev;
	int max_wqes;
	int err = 0;
	int npages;
	int totsz;
	int i;

	ddev = &dev->mdev->pdev->dev;
	max_wqes = dcd->max_wqes;
	totsz = max_wqes * MLX5_DC_CNAK_SIZE;
	npages = DIV_ROUND_UP(totsz, PAGE_SIZE);
	desc = rx ? &dcd->rxdesc : &dcd->txdesc;
	*desc = kcalloc(npages, sizeof(*dcd->rxdesc), GFP_KERNEL);
	if (!*desc) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < npages; i++) {
		d = *desc + i;
		d->buf = dma_alloc_coherent(ddev, PAGE_SIZE, &d->dma, GFP_KERNEL);
		if (!d->buf) {
			mlx5_ib_err(dev, "dma alloc failed at %d\n", i);
			goto out_free;
		}
	}
	if (rx)
		dcd->rx_npages = npages;
	else
		dcd->tx_npages = npages;

	return 0;

out_free:
	for (i--; i >= 0; i--) {
		d = *desc + i;
		dma_free_coherent(ddev, PAGE_SIZE, d->buf, d->dma);
	}
	kfree(*desc);
out:
	return err;
}

static int alloc_dc_rx_buf(struct mlx5_dc_data *dcd)
{
	return alloc_dc_buf(dcd, 1);
}

static int alloc_dc_tx_buf(struct mlx5_dc_data *dcd)
{
	return alloc_dc_buf(dcd, 0);
}

static void free_dc_buf(struct mlx5_dc_data *dcd, int rx)
{
	struct mlx5_ib_dev *dev = dcd->dev;
	struct mlx5_dc_desc *desc;
	struct mlx5_dc_desc *d;
	struct device *ddev;
	int npages;
	int i;

	ddev = &dev->mdev->pdev->dev;
	npages = rx ? dcd->rx_npages : dcd->tx_npages;
	desc = rx ? dcd->rxdesc : dcd->txdesc;
	for (i = 0; i < npages; i++) {
		d = desc + i;
		dma_free_coherent(ddev, PAGE_SIZE, d->buf, d->dma);
	}
	kfree(desc);
}

static void free_dc_rx_buf(struct mlx5_dc_data *dcd)
{
	free_dc_buf(dcd, 1);
}

static void free_dc_tx_buf(struct mlx5_dc_data *dcd)
{
	free_dc_buf(dcd, 0);
}

struct dc_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_dc_data *, struct dc_attribute *, char *buf);
	ssize_t (*store)(struct mlx5_dc_data *, struct dc_attribute *,
			 const char *buf, size_t count);
};

#define DC_ATTR(_name, _mode, _show, _store) \
struct dc_attribute dc_attr_##_name = __ATTR(_name, _mode, _show, _store)

static ssize_t rx_connect_show(struct mlx5_dc_data *dcd,
			       struct dc_attribute *unused,
			       char *buf)
{
	unsigned long num;

	num = dcd->connects;

	return sprintf(buf, "%lu\n", num);
}

static ssize_t tx_cnak_show(struct mlx5_dc_data *dcd,
			    struct dc_attribute *unused,
			    char *buf)
{
	unsigned long num;

	num = dcd->cnaks;

	return sprintf(buf, "%lu\n", num);
}

static ssize_t tx_discard_show(struct mlx5_dc_data *dcd,
			       struct dc_attribute *unused,
			       char *buf)
{
	unsigned long num;

	num = dcd->discards;

	return sprintf(buf, "%lu\n", num);
}

#define DC_ATTR_RO(_name) \
struct dc_attribute dc_attr_##_name = __ATTR_RO(_name)

static DC_ATTR_RO(rx_connect);
static DC_ATTR_RO(tx_cnak);
static DC_ATTR_RO(tx_discard);

static struct attribute *dc_attrs[] = {
	&dc_attr_rx_connect.attr,
	&dc_attr_tx_cnak.attr,
	&dc_attr_tx_discard.attr,
	NULL
};

static ssize_t dc_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct dc_attribute *dc_attr = container_of(attr, struct dc_attribute, attr);
	struct mlx5_dc_data *d = container_of(kobj, struct mlx5_dc_data, kobj);

	if (!dc_attr->show)
		return -EIO;

	return dc_attr->show(d, dc_attr, buf);
}

static const struct sysfs_ops dc_sysfs_ops = {
	.show = dc_attr_show
};

static struct kobj_type dc_type = {
	.sysfs_ops     = &dc_sysfs_ops,
	.default_attrs = dc_attrs
};

static int init_sysfs(struct mlx5_ib_dev *dev)
{
	struct device *device = &dev->ib_dev.dev;

	dev->dc_kobj = kobject_create_and_add("dct", &device->kobj);
	if (!dev->dc_kobj) {
		mlx5_ib_err(dev, "failed to register DCT sysfs object\n");
		return -ENOMEM;
	}

	return 0;
}

static void cleanup_sysfs(struct mlx5_ib_dev *dev)
{
	if (dev->dc_kobj) {
		kobject_put(dev->dc_kobj);
		dev->dc_kobj = NULL;
	}
}

static int init_port_sysfs(struct mlx5_dc_data *dcd)
{
	return kobject_init_and_add(&dcd->kobj, &dc_type, dcd->dev->dc_kobj,
				    "%d", dcd->port);
}

static void cleanup_port_sysfs(struct mlx5_dc_data *dcd)
{
	kobject_put(&dcd->kobj);
}

static int init_driver_cnak(struct mlx5_ib_dev *dev, int port)
{
	int ncqe = 1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz);
	struct mlx5_dc_data *dcd = &dev->dcd[port - 1];
	struct mlx5_ib_resources *devr = &dev->devr;
	struct ib_cq_init_attr cq_attr = {};
	struct ib_qp_init_attr init_attr;
	struct ib_pd *pd = devr->p0;
	struct ib_qp_attr attr;
	int err;
	int i;

	dcd->dev = dev;
	dcd->port = port;
	dcd->mr = pd->device->ops.get_dma_mr(pd,  IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(dcd->mr)) {
		mlx5_ib_warn(dev, "failed to create dc DMA MR\n");
		err = PTR_ERR(dcd->mr);
		goto error1;
	}

	dcd->mr->device      = pd->device;
	dcd->mr->pd          = pd;
	dcd->mr->uobject     = NULL;
	dcd->mr->need_inval  = false;

	cq_attr.cqe = ncqe;
	dcd->rcq = ib_create_cq(&dev->ib_dev, dc_cnack_rcv_comp_handler, NULL,
				dcd, &cq_attr);
	if (IS_ERR(dcd->rcq)) {
		err = PTR_ERR(dcd->rcq);
		mlx5_ib_warn(dev, "failed to create dc cnack rx cq (%d)\n", err);
		goto error2;
	}

	err = ib_req_notify_cq(dcd->rcq, IB_CQ_NEXT_COMP);
	if (err) {
		mlx5_ib_warn(dev, "failed to setup dc cnack rx cq (%d)\n", err);
		goto error3;
	}

	dcd->scq = ib_create_cq(&dev->ib_dev, NULL, NULL,
				dcd, &cq_attr);
	if (IS_ERR(dcd->scq)) {
		err = PTR_ERR(dcd->scq);
		mlx5_ib_warn(dev, "failed to create dc cnack tx cq (%d)\n", err);
		goto error3;
	}

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.qp_type = MLX5_IB_QPT_SW_CNAK;
	init_attr.cap.max_recv_wr = ncqe;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_wr = ncqe;
	init_attr.cap.max_send_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	init_attr.recv_cq = dcd->rcq;
	init_attr.send_cq = dcd->scq;
	dcd->dcqp = ib_create_qp(pd, &init_attr);
	if (IS_ERR(dcd->dcqp)) {
		mlx5_ib_warn(dev, "failed to create qp (%d)\n", err);
		err = PTR_ERR(dcd->dcqp);
		goto error4;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_INIT;
	attr.port_num = port;
	err = ib_modify_qp(dcd->dcqp, &attr,
			   IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT);
	if (err) {
		mlx5_ib_warn(dev, "failed to modify qp to init\n");
		goto error5;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_RTR;
	attr.path_mtu = IB_MTU_4096;
	err = ib_modify_qp(dcd->dcqp, &attr, IB_QP_STATE);
	if (err) {
		mlx5_ib_warn(dev, "failed to modify qp to rtr\n");
		goto error5;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_RTS;
	err = ib_modify_qp(dcd->dcqp, &attr, IB_QP_STATE);
	if (err) {
		mlx5_ib_warn(dev, "failed to modify qp to rts\n");
		goto error5;
	}

	dcd->max_wqes = ncqe;
	err = alloc_dc_rx_buf(dcd);
	if (err) {
		mlx5_ib_warn(dev, "failed to allocate rx buf\n");
		goto error5;
	}

	err = alloc_dc_tx_buf(dcd);
	if (err) {
		mlx5_ib_warn(dev, "failed to allocate tx buf\n");
		goto error6;
	}

	for (i = 0; i < ncqe; i++) {
		err = mlx5_post_one_rxdc(dcd, i);
		if (err)
			goto error7;
	}

	err = init_port_sysfs(dcd);
	if (err) {
		mlx5_ib_warn(dev, "failed to initialize DC cnak sysfs\n");
		goto error7;
	}

	dcd->initialized = 1;
	return 0;

error7:
	free_dc_tx_buf(dcd);
error6:
	free_dc_rx_buf(dcd);
error5:
	if (ib_destroy_qp(dcd->dcqp))
		mlx5_ib_warn(dev, "failed to destroy dc qp\n");
error4:
	if (ib_destroy_cq(dcd->scq))
		mlx5_ib_warn(dev, "failed to destroy dc scq\n");
error3:
	if (ib_destroy_cq(dcd->rcq))
		mlx5_ib_warn(dev, "failed to destroy dc rcq\n");
error2:
	ib_dereg_mr(dcd->mr);
error1:
	return err;
}

static void cleanup_driver_cnak(struct mlx5_ib_dev *dev, int port)
{
	struct mlx5_dc_data *dcd = &dev->dcd[port - 1];

	if (!dcd->initialized)
		return;

	cleanup_port_sysfs(dcd);

	if (ib_destroy_qp(dcd->dcqp))
		mlx5_ib_warn(dev, "destroy qp failed\n");

	if (ib_destroy_cq(dcd->scq))
		mlx5_ib_warn(dev, "destroy scq failed\n");

	if (ib_destroy_cq(dcd->rcq))
		mlx5_ib_warn(dev, "destroy rcq failed\n");

	ib_dereg_mr(dcd->mr);
	free_dc_tx_buf(dcd);
	free_dc_rx_buf(dcd);
	dcd->initialized = 0;
}

int mlx5_ib_init_dc_improvements(struct mlx5_ib_dev *dev)
{
	int port;
	int err;

	if (!mlx5_core_is_pf(dev->mdev) ||
	    !(MLX5_CAP_GEN(dev->mdev, dc_cnak_trace)))
		return 0;

	mlx5_ib_enable_dc_tracer(dev);

	err = init_sysfs(dev);
	if (err)
		return err;

	if (!MLX5_CAP_GEN(dev->mdev, dc_connect_qp))
		return 0;

	for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++) {
		err = init_driver_cnak(dev, port);
		if (err)
			goto out;
	}

	return 0;

out:
	for (port--; port >= 1; port--)
		cleanup_driver_cnak(dev, port);
	cleanup_sysfs(dev);

	return err;
}

void mlx5_ib_cleanup_dc_improvements(struct mlx5_ib_dev *dev)
{
	int port;

	for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++)
		cleanup_driver_cnak(dev, port);
	cleanup_sysfs(dev);

	mlx5_ib_disable_dc_tracer(dev);
}
