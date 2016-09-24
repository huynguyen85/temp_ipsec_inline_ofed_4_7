#ifndef UVERBS_EXP_H
#define UVERBS_EXP_H

#include <linux/kref.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/cdev.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>

struct ib_udct_object {
	struct ib_uevent_object	uevent;
};


unsigned long ib_uverbs_exp_get_unmapped_area(struct file *filp,
					      unsigned long addr,
					      unsigned long len, unsigned long pgoff,
					      unsigned long flags);
long ib_uverbs_exp_ioctl(struct file *filp,
			 unsigned int cmd, unsigned long arg);

void ib_uverbs_async_handler(struct ib_uverbs_file *file,
			     __u64 element, __u64 event,
			     struct list_head *obj_list,
			     u32 *counter);
void ib_uverbs_dct_event_handler(struct ib_event *event, void *context_ptr);

#endif
