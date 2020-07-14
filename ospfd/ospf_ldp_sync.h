/**
 * ospf_ldp_sync.h: OSPF LDP-IGP Sync  handling routines
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
#ifndef _ZEBRA_OSPF_LDP_SYNC_H
#define _ZEBRA_OSPF_LDP_SYNC_H

#define LDP_OSPF_LSINFINITY 65535

/* Macro to log debug message */
#define ols_debug(...)                                                         \
	do {                                                                   \
		if (IS_DEBUG_OSPF_LDP_SYNC)                                    \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)


extern void ospf_if_set_ldp_sync_enable(struct ospf *, struct interface *);
extern void ospf_if_set_ldp_sync_holddown(struct ospf *, struct interface *);
extern void ospf_ldp_sync_if_init(struct ospf_interface *);
extern void ospf_ldp_sync_if_start(struct interface *, bool);
extern void ospf_ldp_sync_if_remove(struct interface *);
extern void ospf_ldp_sync_if_down(struct interface *);
extern void ospf_ldp_sync_if_complete(struct interface *);
extern void ospf_ldp_sync_holddown_timer_add(struct interface *);
extern void ospf_ldp_sync_hello_timer_add(struct ospf *);
extern void ospf_ldp_sync_ldp_fail(struct interface *);
extern void ospf_ldp_sync_show_info(struct vty *, struct ospf *, json_object *,
				    bool);
extern void ospf_ldp_sync_write_config(struct vty *, struct ospf *);
extern void ospf_ldp_sync_if_write_config(struct vty *, struct ospf_if_params *);
extern int ospf_ldp_sync_state_update(struct ldp_igp_sync_if_state);
extern int ospf_ldp_sync_announce_update(struct ldp_igp_sync_announce);
extern int ospf_ldp_sync_hello_update(struct ldp_igp_sync_hello);
extern void ospf_ldp_sync_state_req_msg(struct interface *);
extern void ospf_ldp_sync_announce_send_msg(bool);
extern void ospf_ldp_sync_init(void);
#endif /* _ZEBRA_OSPF_LDP_SYNC_H */
