/**
 * isis_ldp_sync.h: ISIS LDP-IGP Sync  handling routines
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
#ifndef _ZEBRA_ISIS_LDP_SYNC_H
#define _ZEBRA_ISIS_LDP_SYNC_H

#define LDP_ISIS_LSINFINITY 65535

extern void isis_if_set_ldp_sync_enable(struct isis_circuit *);
extern void isis_if_set_ldp_sync_holddown(struct  isis_circuit *);
extern void isis_ldp_sync_if_init(struct isis_circuit *);
extern void isis_ldp_sync_if_start(struct isis_circuit *, bool);
extern void isis_ldp_sync_if_remove(struct isis_circuit *);
extern void isis_ldp_sync_if_complete(struct isis_circuit *);
extern void isis_ldp_sync_holddown_timer_add(struct isis_circuit *);
extern void isis_ldp_sync_hello_timer_add(void);
extern void isis_ldp_sync_ldp_fail(struct isis_circuit *);
extern int isis_ldp_sync_state_update(struct ldp_igp_sync_if_state);
extern int isis_ldp_sync_announce_update(struct ldp_igp_sync_announce);
extern int isis_ldp_sync_hello_update(struct ldp_igp_sync_hello);
extern void isis_ldp_sync_state_req_msg(struct isis_circuit *);
extern void isis_ldp_sync_set_if_metric(struct isis_circuit *);
extern void isis_ldp_sync_init(void);
#endif /* _ZEBRA_ISIS_LDP_SYNC_H */
