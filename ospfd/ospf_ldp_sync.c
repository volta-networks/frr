/**
 * ospf_ldp_sync.c: OSPF LDP-IGP Sync  handling routines
 *
 * @copyright Copyright (C) 2020 Volta Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <string.h>

#include "monotime.h"
#include "memory.h"
#include "thread.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "plist.h"
#include "log.h"
#include "zclient.h"
#include <lib/json.h>
#include "defaults.h"
#include "ldp_sync.h"

#include "ospfd.h"
#include "ospf_interface.h"
#include "ospf_vty.h"
#include "ospf_ldp_sync.h"
#include "ospf_dump.h"
#include "ospf_ism.h"


/*
 * ospf_ldp_sync_info_free - Free LDP info structure
 */
void ospf_ldp_sync_info_free(struct ospf_if_params *oip)
{
	if (oip->ldp_sync_info) {
		if (oip->ldp_sync_info->t_holddown != NULL)
			THREAD_TIMER_OFF(oip->ldp_sync_info->t_holddown);

		ldp_sync_info_free((struct ldp_sync_info **)
				   &(oip->ldp_sync_info));
	}
}

/*
 * LDP-SYNC msg between IGP and LDP
 */
int ldp_igp_opaque_msg_handler(ZAPI_CALLBACK_ARGS)
{
	uint32_t type;
	struct ldp_igp_sync_if_state state;
	struct stream *s;
	struct interface *ifp;

	s = zclient->ibuf;
	STREAM_GETL(s, type);

	switch (type) {
	case LDP_IGP_SYNC_IF_STATE_UPDATE:
                STREAM_GET(&state, s, sizeof(state));
		ifp = if_lookup_by_index(state.ifindex, VRF_DEFAULT);
		if (ifp) {
			if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
				zlog_debug("ldp_sync: rcvd %s from LDP if %s",
					state.sync_start
					? "sync-start"
					: "sync-complete",
					ifp->name);
			if (state.sync_start)
				ospf_ldp_sync_if_sync_start(ifp);
			else
				ospf_ldp_sync_if_sync_complete(ifp);
			break;
		}
	default:
		break;
	}

stream_failure:

        return 0;
}

/*
 * LDP-SYNC general interface routines
 */

void ospf_ldp_sync_if_init(struct ospf_interface *oi)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	/* called when OSPF is configured on an interface
	 *  if LDP-IGP Sync is configured globally
	 *  set state
         *  and if ptop interface inform LDP LDP-SYNC is enabled
         */
	if (!(CHECK_FLAG(oi->ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)))
		return;

	params = IF_DEF_PARAMS(oi->ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();
	ldp_sync_info = params->ldp_sync_info;

	/* specifed on interface overrides global config. */
	if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		ldp_sync_info->holddown = oi->ospf->ldp_sync_cmd.holddown;

	if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG))
		ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;

	if (params->type == OSPF_IFTYPE_POINTOPOINT &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED) {
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
			ospf_ldp_sync_igp_send_msg(oi->ifp, true);
	}
}

void ospf_ldp_sync_if_sync_start(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	/* Start LDP-SYNC on this interface:
	 * set cost of interface to LSInfinity so traffic will use different
         * interface until LDP has learned all labels from peer and
	 * start holddown timer if configured
	 */
	if (ldp_sync_info &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED &&
	    ldp_sync_info->state != LDP_IGP_SYNC_STATE_NOT_REQUIRED) {
		if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
			zlog_debug("ldp_sync: sync start on if %s state: %s",
				ifp->name, "Holding down until Sync");
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		ospf_if_recalculate_output_cost(ifp);
		ospf_ldp_sync_holddown_timer_add(ifp);
	}
}

void ospf_ldp_sync_if_down(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	if (ldp_sync_info == NULL)
		return;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("ldp_sync: down on if %s", ifp->name);

	ldp_sync_if_down(params->ldp_sync_info);

	/* Interface down:
	 *   can occur from a link down or changing config
	 *   ospf network type change if is brought down/up
	 *   send msg to LDP indicating if LDP-SYNC is enabled or disabled
	 *   restore cost
	 */
	switch (ldp_sync_info->state) {
	case LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP:
	case LDP_IGP_SYNC_STATE_REQUIRED_UP:
		if (params->type != OSPF_IFTYPE_POINTOPOINT) {
			/* LDP-SYNC not able to run on non-ptop interface */
			ospf_ldp_sync_igp_send_msg(ifp, false);
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
			ospf_if_recalculate_output_cost(ifp);
		}
		break;
	case LDP_IGP_SYNC_STATE_NOT_REQUIRED:
		if (params->type == OSPF_IFTYPE_POINTOPOINT) {
			/* LDP-SYNC is able to run on ptop interface */
			ospf_ldp_sync_igp_send_msg(ifp, true);
			ldp_sync_info->state =
				LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		}
		break;
	default:
		break;
	}
}

void ospf_ldp_sync_if_remove(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	/* Stop LDP-SYNC on this interface:
	 *   if holddown timer is running stop it
	 *   return ospf cost to original value
	 *   send msg to LDP to stop running LDP-SYNC on this interface
	 *   delete ldp instance on interface
	 */
	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("ldp_sync: Removed from if %s",ifp->name);

	if (ldp_sync_info->t_holddown != NULL) {
		THREAD_TIMER_OFF(ldp_sync_info->t_holddown);
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
		ospf_if_recalculate_output_cost(ifp);
	}

	ospf_ldp_sync_igp_send_msg(ifp, false);
	ospf_ldp_sync_info_free(params);
}

static int ospf_ldp_sync_ism_change(struct ospf_interface *oi, int state,
	                            int old_state)
{
	/* Terminal state or regression */
	switch (state) {
	case ISM_PointToPoint:
		if (oi->type == OSPF_IFTYPE_POINTOPOINT)
			/* If LDP-SYNC is configure on interface then start */
			ospf_ldp_sync_if_sync_start(oi->ifp);
		break;
	case ISM_Down:
		/* If LDP-SYNC is configure on this interface then stop it */
		ospf_ldp_sync_if_down(oi->ifp);
		break;
	default:
		break;
	}
	return 0;
}

void ospf_ldp_sync_igp_send_msg(struct interface *ifp, bool state)
{
	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("ldp_sync: send %s to LDP if %s",
			state ? "enable" : "disable", ifp->name);

	ldp_sync_igp_send_msg(ifp, state);
}

/*
 * LDP-SYNC holddown timer routines
 */
static int ospf_ldp_sync_holddown_timer(struct thread *thread)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	/* holddown timer expired:
         *  didn't receive msg from LDP indicating sync-complete
         *  restore interface cost to original value
	 */
	ifp = THREAD_ARG(thread);
	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_UP;
	ldp_sync_info->t_holddown = NULL;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("ldp_sync: holddown timer expired for %s state: %s",
			   ifp->name, "Sync achieved");

	ospf_if_recalculate_output_cost(ifp);
	return 0;
}

void ospf_ldp_sync_holddown_timer_add(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	/* Start holddown timer:
         *  this timer is used to keep interface cost at LSInfinity
         *  once expires returns cost to original value
	 *  if timer is already running or holddown time is off just return
         */
	if (ldp_sync_info->t_holddown ||
	    ldp_sync_info->holddown == LDP_IGP_SYNC_HOLDDOWN_DEFAULT)
		return;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("ldp_sync: start holddown timer for %s time %d",
			   ifp->name, ldp_sync_info->holddown);

	/* Set timer. */
	thread_add_timer(master, ospf_ldp_sync_holddown_timer,
			 ifp, ldp_sync_info->holddown,
			 &ldp_sync_info->t_holddown);
}

void ospf_ldp_sync_if_sync_complete(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	/* received sync-complete from LDP:
         *  set state to up
	 *  stop timer
	 *  restore interface cost to original value
         */
	if (ldp_sync_info) {
		if (ldp_sync_info->state == LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP)
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_UP;
		THREAD_TIMER_OFF(ldp_sync_info->t_holddown);
		ldp_sync_info->t_holddown = NULL;
		ospf_if_recalculate_output_cost(ifp);
	}
}

/*
 * LDP-SYNC routes used by set commands.
 */

void ospf_if_set_ldp_sync_enable(struct ospf *ospf, struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	/* called when setting LDP-SYNC at the global level:
         *  specifed on interface overrides global config
         *  if ptop link send msg to LDP indicating ldp-sync enabled
         */
	params = IF_DEF_PARAMS(ifp);
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		if (params->ldp_sync_info == NULL)
			params->ldp_sync_info = ldp_sync_info_create();
		ldp_sync_info = params->ldp_sync_info;

		/* config on interface, overrides global config. */
		if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG))
			return;

		ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;

		if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
			zlog_debug("ldp_sync: enable if %s", ifp->name);

		/* send message to LDP if ptop link */
		if (params->type == OSPF_IFTYPE_POINTOPOINT) {
			ldp_sync_info->state =
				LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
			ospf_ldp_sync_igp_send_msg(ifp, true);
		} else {
			params->ldp_sync_info->state =
				LDP_IGP_SYNC_STATE_NOT_REQUIRED;
			zlog_debug("ldp_sync: Sync only runs on P2P links %s",
				   ifp->name);
		}
	} else {
		/* delete LDP sync even if configured on an interface */
		if (params->ldp_sync_info)
			ospf_ldp_sync_if_remove(ifp);
	}
}

void ospf_if_set_ldp_sync_holddown(struct ospf *ospf, struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	/* called when setting LDP-SYNC at the global level:
	 *  specifed on interface overrides global config.
	 */
	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();
	ldp_sync_info = params->ldp_sync_info;

	/* config on interface, overrides global config. */
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		return;
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN))
		ldp_sync_info->holddown = ospf->ldp_sync_cmd.holddown;
	else
		ldp_sync_info->holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
}

/*
 * LDP-SYNC routines used by show commands.
 */

void ospf_ldp_sync_show_info(struct vty *vty, struct ospf *ospf,
			     json_object *json_vrf, bool use_json)
{

	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		if (use_json) {
			json_object_boolean_true_add(json_vrf,
						     "MplsLdpIgpSyncEnabled");
			json_object_int_add(json_vrf,"MplsLdpIgpSyncHolddown",
					    ospf->ldp_sync_cmd.holddown);
		} else {
			vty_out(vty, " MPLS LDP-IGP Sync is enabled\n");
			if (ospf->ldp_sync_cmd.holddown == 0)
				vty_out(vty, " MPLS LDP-IGP Sync holddown timer is disabled\n");
			else
				vty_out(vty, " MPLS LDP-IGP Sync holddown timer %d sec\n",
					ospf->ldp_sync_cmd.holddown);
		}
	}
}

static void show_ip_ospf_mpls_ldp_interface_sub(struct vty *vty,
					       struct ospf_interface *oi,
					       struct interface *ifp,
					       json_object *json_interface_sub,
					       bool use_json)
{
	const char *ldp_state;
	struct ospf_if_params *params;
	char timebuf[OSPF_TIME_DUMP_SIZE];
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(oi->ifp);
	ldp_sync_info = params->ldp_sync_info;
	if (ldp_sync_info == NULL)
		return;

	if (use_json) {
		if (ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED)
			json_object_boolean_true_add(json_interface_sub,
						     "ldpIgpSyncEnabled");
		else
			json_object_boolean_true_add(json_interface_sub,
						     "ldpIgpSyncDisabled");

		json_object_int_add(json_interface_sub, "holdDownTimeInSec",
				    ldp_sync_info->holddown);

	} else {
		vty_out(vty,"%-10s\n", ifp->name);
		vty_out(vty,"  LDP-IGP Synchronization enabled: %s\n",
			ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED
			? "yes"
			: "no");
		vty_out(vty,"  holddown timer in seconds: %u\n",
			ldp_sync_info->holddown);
	}

	switch (params->ldp_sync_info->state) {
	case LDP_IGP_SYNC_STATE_REQUIRED_UP:
		if (use_json)
			json_object_string_add(json_interface_sub,
					       "ldpIgpSyncState",
					       "Sync achieved");
		else
			vty_out(vty,"  State: Sync achieved\n");
		break;
	case LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP:
		if (ldp_sync_info->t_holddown != NULL) {
			if (use_json) {
				long time_store;
				time_store = monotime_until(
					&ldp_sync_info->t_holddown->u.sands,
					NULL)
					/1000LL;
				json_object_int_add(json_interface_sub,
						    "ldpIgpSyncTimeRemainInMsec",
						    time_store);

				json_object_string_add(json_interface_sub,
						       "ldpIgpSyncState",
						       "Holding down until Sync");
			} else {
				vty_out(vty,"  Holddown timer is running %s remaining\n",
					ospf_timer_dump(
						ldp_sync_info->t_holddown,
						timebuf,
						sizeof(timebuf)));

				vty_out(vty,"  State: Holding down until Sync\n");
			}
		} else {
			if (use_json)
				json_object_string_add(json_interface_sub,
						       "ldpIgpSyncState",
						       "Sync not achieved");
			else
				vty_out(vty,"  State: Sync not achieved\n");
		}
		break;
	case LDP_IGP_SYNC_STATE_NOT_REQUIRED:
	default:
		if (IF_DEF_PARAMS(ifp)->type != OSPF_IFTYPE_POINTOPOINT)
			ldp_state = "Sync not required: non-p2p link";
		else
			ldp_state = "Sync not required";

		if (use_json)
			json_object_string_add(json_interface_sub,
					       "ldpIgpSyncState",
					       ldp_state);
		else
			vty_out(vty,"  State: %s\n", ldp_state);
		break;
	}
}

static int show_ip_ospf_mpls_ldp_interface_common(struct vty *vty,
						  struct ospf *ospf,
						  char *intf_name,
						  json_object *json,
						  bool use_json)
{
	struct interface *ifp;
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	json_object *json_interface_sub = NULL;

	if (intf_name == NULL) {
		/* Show All Interfaces.*/
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct route_node *rn;
			struct ospf_interface *oi;

			if (ospf_oi_count(ifp) == 0)
				continue;
			for (rn = route_top(IF_OIFS(ifp)); rn;
			     rn = route_next(rn)) {
				oi = rn->info;

				if (use_json) {
					json_interface_sub =
						json_object_new_object();
				}
				show_ip_ospf_mpls_ldp_interface_sub(
					vty, oi, ifp, json_interface_sub,
					use_json);

				if (use_json) {
					json_object_object_add(
						json, ifp->name,
						json_interface_sub);
				}
			}
		}
	} else {
		/* Interface name is specified. */
		ifp = if_lookup_by_name(intf_name, ospf->vrf_id);
		if (ifp != NULL) {
			struct route_node *rn;
			struct ospf_interface *oi;

			if (ospf_oi_count(ifp) == 0) {
				vty_out(vty,
					"  OSPF not enabled on this interface %s\n",
					ifp->name);
				return CMD_SUCCESS;
			}
			for (rn = route_top(IF_OIFS(ifp)); rn;
			     rn = route_next(rn)) {
				oi = rn->info;

				if (use_json)
					json_interface_sub =
						json_object_new_object();

				show_ip_ospf_mpls_ldp_interface_sub(
					vty, oi, ifp, json_interface_sub,
					use_json);

				if (use_json) {
					json_object_object_add(
						json,	ifp->name,
						json_interface_sub);
				}
			}
		}
	}
	return CMD_SUCCESS;
}

/*
 * Write the global LDP-SYNC configuration.
 */
void ospf_ldp_sync_write_config(struct vty *vty, struct ospf *ospf)
{
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		vty_out(vty, " mpls ldp-sync\n");
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN))
		vty_out(vty, " mpls ldp-sync holddown %u\n",
			ospf->ldp_sync_cmd.holddown);
}

/*
 * Write the interface LDP-SYNC configuration.
 */
void ospf_ldp_sync_if_write_config(struct vty *vty,
				   struct ospf_if_params *params)

{
	struct ldp_sync_info *ldp_sync_info;

	ldp_sync_info = params->ldp_sync_info;
	if (ldp_sync_info == NULL)
		return;

	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG)) {
		if (ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED)
			vty_out(vty, " mpls ldp-sync\n");
		else
			vty_out(vty, " no mpls ldp-sync\n");
	}
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		vty_out(vty, " mpls ldp-sync holddown %u\n",
			ldp_sync_info->holddown);
}

/*
 * LDP-SYNC commands.
 */

DEFUN (ospf_mpls_ldp_sync,
       ospf_mpls_ldp_sync_cmd,
       "mpls ldp-sync",
       "MPLS specific commands\n"
       "Enable MPLS LDP-IGP Sync\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;

	if (!CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		SET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);
		/* turn on LDP-IGP Sync on all ptop OSPF interfaces */
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf_if_set_ldp_sync_enable(ospf, ifp);
	}
	return CMD_SUCCESS;
}

DEFUN (no_ospf_mpls_ldp_sync,
       no_ospf_mpls_ldp_sync_cmd,
       "no mpls ldp-sync",
       NO_STR
       "MPLS specific commands\n"
       "Disable MPLS LDP-IGP Sync\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;

	/* if you delete LDP-SYNC at a gobal level is clears all LDP-SYNC
	 * configuration, even interface configuration
         */
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		UNSET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);
		UNSET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
		ospf->ldp_sync_cmd.holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;

		/* turn off LDP-IGP Sync on all OSPF interfaces */
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf_if_set_ldp_sync_enable(ospf, ifp);
	}
	return CMD_SUCCESS;
}

DEFUN (ospf_mpls_ldp_sync_holddown,
       ospf_mpls_ldp_sync_holddown_cmd,
       "mpls ldp-sync holddown (1-10000)",
       "MPLS specific commands\n"
       "Enable MPLS LDP-IGP Sync\n"
       "Set holddown timer\n"
       "seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	uint16_t holddown = 0;
	int idx_number = 3;
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;

	holddown = strtoul(argv[idx_number]->arg, NULL, 10);

	SET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
	ospf->ldp_sync_cmd.holddown = holddown;
	/* set holddown time on all OSPF interfaces */
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_if_set_ldp_sync_holddown(ospf, ifp);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_mpls_ldp_sync_holddown,
       no_ospf_mpls_ldp_sync_holddown_cmd,
       "no mpls ldp-sync holddown",
       NO_STR
       "MPLS specific commands\n"
       "Disable MPLS LDP-IGP Sync\n"
       "holddown timer disable\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;

	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN)) {
		UNSET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
		ospf->ldp_sync_cmd.holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
		/* turn off holddown timer on all OSPF interfaces */
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf_if_set_ldp_sync_holddown(ospf, ifp);
	}
	return CMD_SUCCESS;
}


DEFUN (mpls_ldp_sync,
       mpls_ldp_sync_cmd,
       "mpls ldp-sync",
       "MPLS information\n"
       "Enable MPLS LDP-IGP Sync\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	zlog_debug("%s if %s",__func__, ifp->name);
	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();
	ldp_sync_info = params->ldp_sync_info;

	SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG);
	ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;
	if (params->type == OSPF_IFTYPE_POINTOPOINT) {
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		ospf_ldp_sync_igp_send_msg(ifp, true);
	} else {
		zlog_debug("ldp_sync: only runs on P2P links %s", ifp->name);
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
	}
	return CMD_SUCCESS;
}

DEFUN (no_mpls_ldp_sync,
       no_mpls_ldp_sync_cmd,
       "no mpls ldp-sync",
       NO_STR
       "MPLS information\n"
       "Disable MPLS LDP-IGP Sync\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;
	bool   ldp_sync_was_running = false;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;
	if (ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();
	ldp_sync_info = params->ldp_sync_info;

	/* disable LDP-SYNC on an interface
         *  stop holddown timer if running
         *  restore ospf cost
         *  send message to LDP
         */
	if (ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED &&
	    ldp_sync_info->t_holddown != NULL)
		    ldp_sync_was_running = true;

	SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG);
	ldp_sync_info->enabled = LDP_IGP_SYNC_DEFAULT;
	ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
	ospf_ldp_sync_igp_send_msg(ifp, false);

	if (ldp_sync_was_running) {
		THREAD_TIMER_OFF(ldp_sync_info->t_holddown);
		ldp_sync_info->t_holddown = NULL;
		ospf_if_recalculate_output_cost(ifp);
	}

	return CMD_SUCCESS;
}

DEFUN (mpls_ldp_sync_holddown,
       mpls_ldp_sync_holddown_cmd,
       "mpls ldp-sync holddown (1-10000)",
       "MPLS information\n"
       "Enable MPLS LDP-IGP Sync\n"
       "Set holddown timer\n"
       "seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	uint16_t holddown = 0;
	int idx_number = 3;
	struct ldp_sync_info *ldp_sync_info;

	holddown = strtoul(argv[idx_number]->arg, NULL, 10);
	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();
	ldp_sync_info = params->ldp_sync_info;

	SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN);
	ldp_sync_info->holddown = holddown;

	return CMD_SUCCESS;
}

DEFUN (no_mpls_ldp_sync_holddown,
       no_mpls_ldp_sync_holddown_cmd,
       "no mpls ldp-sync holddown",
       NO_STR
       "MPLS information\n"
       "Disable MPLS LDP-IGP Sync\n"
       "holddown timer disable\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;
	if (ldp_sync_info == NULL)
		return CMD_SUCCESS;

	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN)) {
		UNSET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN);
		ldp_sync_info->holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_mpls_ldp_interface,
       show_ip_ospf_mpls_ldp_interface_cmd,
       "show ip ospf mpls ldp [interface <INTERFACE|all>] [json]",
       SHOW_STR
       IP_STR
       "LDP-IGP Sync information\n"
       MPLS_STR
       "LDP-IGP Sync information\n"
       "Interface name\n"
       JSON_STR)
{
	struct ospf *ospf;
	bool uj = use_json(argc, argv);
	char *intf_name = NULL;
	int ret = CMD_SUCCESS;
	int idx_intf = 0;
	json_object *json = NULL;

	if (argv_find(argv, argc, "INTERFACE", &idx_intf))
		intf_name = argv[idx_intf]->arg;

	if (uj)
		json = json_object_new_object();

	/* Display default ospf (instance 0) info */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL || !ospf->oi_running) {
		if (uj) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
			json_object_free(json);
		} else
			vty_out(vty, "%% OSPF instance not found\n");
		return CMD_SUCCESS;
	}
	ret = show_ip_ospf_mpls_ldp_interface_common(vty, ospf, intf_name,
						     json, uj);
	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return ret;
}

void ospf_ldp_sync_init(void)
{
	/* Install global ldp-igp sync commands */
	install_element(OSPF_NODE, &ospf_mpls_ldp_sync_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_ldp_sync_cmd);
	install_element(OSPF_NODE, &ospf_mpls_ldp_sync_holddown_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_ldp_sync_holddown_cmd);

	/* Interface lsp-igp sync commands */
	install_element(INTERFACE_NODE, &mpls_ldp_sync_cmd);
	install_element(INTERFACE_NODE, &no_mpls_ldp_sync_cmd);
	install_element(INTERFACE_NODE, &mpls_ldp_sync_holddown_cmd);
	install_element(INTERFACE_NODE, &no_mpls_ldp_sync_holddown_cmd);

	/* "show ip ospf mpls ldp interface" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_mpls_ldp_interface_cmd);

	hook_register(ospf_ism_change, ospf_ldp_sync_ism_change);

}
