/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BLK_MQ_RDMA_H
#define _LINUX_BLK_MQ_RDMA_H

struct blk_mq_tag_set;
struct ib_device;

#define blk_mq_rdma_map_queues LINUX_BACKPORT(blk_mq_rdma_map_queues)
int blk_mq_rdma_map_queues(struct blk_mq_queue_map *map,
		struct ib_device *dev, int first_vec);

#endif /* _LINUX_BLK_MQ_RDMA_H */
