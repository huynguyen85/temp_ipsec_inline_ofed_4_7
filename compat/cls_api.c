// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/cls_api.c	Packet classifier API.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Changes:
 *
 * Eduardo J. Blanco <ejbs@netlabs.com.uy> :990222: kmod support
 */

#ifndef HAVE_TC_SETUP_FLOW_ACTION

#include <net/pkt_cls.h>
#include <net/flow_offload.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <net/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_csum.h>
#include <net/tc_act/tc_skbedit.h>
#include <net/tc_act/tc_sample.h>

int tc_setup_flow_action(struct flow_action *flow_action,
			 const struct tcf_exts *exts)
{
	const struct tc_action *act;
	int i, j, k;

	if (!exts)
		return 0;

	j = 0;
	tcf_exts_for_each_action(i, act, exts) {
		struct flow_action_entry *entry;

		entry = &flow_action->entries[j];
		if (is_tcf_gact_ok(act)) {
			entry->id = FLOW_ACTION_ACCEPT;
		} else if (is_tcf_gact_shot(act)) {
			entry->id = FLOW_ACTION_DROP;
		} else if (is_tcf_gact_trap(act)) {
			entry->id = FLOW_ACTION_TRAP;
		} else if (is_tcf_gact_goto_chain(act)) {
			entry->id = FLOW_ACTION_GOTO;
			entry->chain_index = tcf_gact_goto_chain_index(act);
		} else if (is_tcf_mirred_egress_redirect(act)) {
			entry->id = FLOW_ACTION_REDIRECT;
			entry->dev = tcf_mirred_dev(act);
		} else if (is_tcf_mirred_egress_mirror(act)) {
			entry->id = FLOW_ACTION_MIRRED;
			entry->dev = tcf_mirred_dev(act);
		} else if (is_tcf_vlan(act)) {
			switch (tcf_vlan_action(act)) {
			case TCA_VLAN_ACT_PUSH:
				entry->id = FLOW_ACTION_VLAN_PUSH;
				entry->vlan.vid = tcf_vlan_push_vid(act);
				entry->vlan.proto = tcf_vlan_push_proto(act);
				entry->vlan.prio = tcf_vlan_push_prio(act);
				break;
			case TCA_VLAN_ACT_POP:
				entry->id = FLOW_ACTION_VLAN_POP;
				break;
			case TCA_VLAN_ACT_MODIFY:
				entry->id = FLOW_ACTION_VLAN_MANGLE;
				entry->vlan.vid = tcf_vlan_push_vid(act);
				entry->vlan.proto = tcf_vlan_push_proto(act);
				entry->vlan.prio = tcf_vlan_push_prio(act);
				break;
			default:
				goto err_out;
			}
		} else if (is_tcf_tunnel_set(act)) {
			entry->id = FLOW_ACTION_TUNNEL_ENCAP;
			entry->tunnel = tcf_tunnel_info(act);
		} else if (is_tcf_tunnel_release(act)) {
			entry->id = FLOW_ACTION_TUNNEL_DECAP;
		} else if (is_tcf_pedit(act)) {
			for (k = 0; k < tcf_pedit_nkeys(act); k++) {
				switch (tcf_pedit_cmd(act, k)) {
				case TCA_PEDIT_KEY_EX_CMD_SET:
					entry->id = FLOW_ACTION_MANGLE;
					break;
				case TCA_PEDIT_KEY_EX_CMD_ADD:
					entry->id = FLOW_ACTION_ADD;
					break;
				default:
					goto err_out;
				}
				entry->mangle.htype = tcf_pedit_htype(act, k);
				entry->mangle.mask = tcf_pedit_mask(act, k);
				entry->mangle.val = tcf_pedit_val(act, k);
				entry->mangle.offset = tcf_pedit_offset(act, k);
				entry = &flow_action->entries[++j];
			}
		} else if (is_tcf_csum(act)) {
			entry->id = FLOW_ACTION_CSUM;
			entry->csum_flags = tcf_csum_update_flags(act);
		} else if (is_tcf_skbedit_mark(act)) {
			entry->id = FLOW_ACTION_MARK;
			entry->mark = tcf_skbedit_mark(act);
		} else if (is_tcf_sample(act)) {
			entry->id = FLOW_ACTION_SAMPLE;
			entry->sample.psample_group =
				tcf_sample_psample_group(act);
			entry->sample.trunc_size = tcf_sample_trunc_size(act);
			entry->sample.truncate = tcf_sample_truncate(act);
			entry->sample.rate = tcf_sample_rate(act);
		}
		/* else if (is_tcf_police(act)) {
			entry->id = FLOW_ACTION_POLICE;
			entry->police.burst = tcf_police_tcfp_burst(act);
			entry->police.rate_bytes_ps =
				tcf_police_rate_bytes_ps(act);
		} */
		else {
			goto err_out;
		}

		if (!is_tcf_pedit(act))
			j++;
	}
	return 0;
err_out:
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(tc_setup_flow_action);

#endif
