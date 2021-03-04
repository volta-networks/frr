/*
 * Copyright (C) 2020 Volta Networks, Inc
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef _PATH_TED_H
#define _PATH_TED_H

#ifdef __cplusplus

extern "C" {
#endif

#include <zebra.h>

#include <stdbool.h>

#include "linklist.h"
#include "log.h"
#include "command.h"
#include "stream.h"
#include "prefix.h"
#include "zclient.h"
#include "link_state.h"

	/* PCEP TED management functions */
	void path_ted_init(struct thread_master *master);
	int path_ted_teardown(void);
	void path_ted_timer_cancel(void);

	/* TED Query functions */

	//
	// Type of queries from draft-ietf-spring-segment-routing-policy-07 for types f,c,e.
	//

	/**
	 * Search for sid based in ipv6
	 *
	 * @param router_id		The ipv6
	 *
	 * @return		sid of attribute
	 */
	struct ls_node *path_ted_query_router_by_ipv6(struct in6_addr router6_id);

	/**
	 * Search for sid based in ipv4
	 *
	 * @param router_id		The ipv4
	 *
	 * @return		sid of attribute
	 */
	struct ls_node *path_ted_query_router_by_ipv4(struct in_addr router_id);

	/**
	 * Search for sid based in local, remote pair
	 *
	 * @param local		local ip of attribute
	 * @param remote	remote ip of attribute
	 *
	 * @return		sid of attribute
	 */
	uint32_t path_ted_query_type_f(struct ipaddr *local, struct ipaddr *remote);

	/**
	 * Search for sid based in prefix and optional algo
	 *
	 * @param prefix	Net prefix to resolv
	 * @param algo		Algorithm for link state
	 *
	 * @return		sid of attribute
	 */
	uint32_t path_ted_query_type_c( struct prefix *prefix, uint8_t algo);

	/**
	 * Search for sid based in prefix and interface id
	 *
	 * @param prefix	Net prefix to resolv
	 * @param iface_id	The interface id
	 *
	 * @return		sid of attribute
	 */
	extern uint32_t path_ted_query_type_e( struct prefix *prefix, uint32_t iface_id);

	/**
	 * Handle the received opaque msg
	 *
	 * @param msg	Holds the ted data
	 * @param key	The key associated to the current node id
	 *
	 * @return		sid of attribute
	 */
	int path_ted_rcvd_message(struct ls_message *msg, uint64_t key);

#ifdef __cplusplus
}
#endif

#endif /* _PATH_TED_H */
