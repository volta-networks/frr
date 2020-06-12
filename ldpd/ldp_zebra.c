/*
 * Copyright (C) 2016 by Open Source Routing.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "command.h"
#include "network.h"
#include "linklist.h"
#include "mpls.h"

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "ldp_sync.h"
#include "log.h"
#include "ldp_debug.h"

static void	 ifp2kif(struct interface *, struct kif *);
static void	 ifc2kaddr(struct interface *, struct connected *,
		    struct kaddr *);
static int	 ldp_zebra_send_mpls_labels(int, struct kroute *);
static int	 ldp_router_id_update(ZAPI_CALLBACK_ARGS);
static int	 ldp_interface_address_add(ZAPI_CALLBACK_ARGS);
static int	 ldp_interface_address_delete(ZAPI_CALLBACK_ARGS);
static int	 ldp_zebra_read_route(ZAPI_CALLBACK_ARGS);
static int	 ldp_zebra_read_pw_status_update(ZAPI_CALLBACK_ARGS);
static void	 ldp_zebra_connected(struct zclient *);
static void	 ldp_zebra_filter_update(struct access_list *access);

static struct zclient	*zclient;

static void
ifp2kif(struct interface *ifp, struct kif *kif)
{
	memset(kif, 0, sizeof(*kif));
	strlcpy(kif->ifname, ifp->name, sizeof(kif->ifname));
	kif->ifindex = ifp->ifindex;
	kif->operative = if_is_operative(ifp);
	if (ifp->ll_type == ZEBRA_LLT_ETHER)
		memcpy(kif->mac, ifp->hw_addr, ETH_ALEN);
}

static void
ifc2kaddr(struct interface *ifp, struct connected *ifc, struct kaddr *ka)
{
	memset(ka, 0, sizeof(*ka));
	strlcpy(ka->ifname, ifp->name, sizeof(ka->ifname));
	ka->ifindex = ifp->ifindex;
	ka->af = ifc->address->family;
	ka->prefixlen = ifc->address->prefixlen;

	switch (ka->af) {
	case AF_INET:
		ka->addr.v4 = ifc->address->u.prefix4;
		if (ifc->destination)
			ka->dstbrd.v4 = ifc->destination->u.prefix4;
		break;
	case AF_INET6:
		ka->addr.v6 = ifc->address->u.prefix6;
		if (ifc->destination)
			ka->dstbrd.v6 = ifc->destination->u.prefix6;
		break;
	default:
		break;
	}
}

void
pw2zpw(struct l2vpn_pw *pw, struct zapi_pw *zpw)
{
	memset(zpw, 0, sizeof(*zpw));
	strlcpy(zpw->ifname, pw->ifname, sizeof(zpw->ifname));
	zpw->ifindex = pw->ifindex;
	zpw->type = pw->l2vpn->pw_type;
	zpw->af = pw->af;
	zpw->nexthop.ipv6 = pw->addr.v6;
	zpw->local_label = NO_LABEL;
	zpw->remote_label = NO_LABEL;
	if (pw->flags & F_PW_CWORD)
		zpw->flags = F_PSEUDOWIRE_CWORD;
	zpw->data.ldp.lsr_id = pw->lsr_id;
	zpw->data.ldp.pwid = pw->pwid;
	strlcpy(zpw->data.ldp.vpn_name, pw->l2vpn->name,
	    sizeof(zpw->data.ldp.vpn_name));
}

static void ldp_zebra_opaque_register(void)
{
	zclient_register_opaque(zclient, LDP_IGP_SYNC_IF_CONFIG_UPDATE);
}

static void ldp_zebra_opaque_unregister(void)
{
	zclient_unregister_opaque(zclient, LDP_IGP_SYNC_IF_CONFIG_UPDATE);
}

int ldp_sync_send_state_update(struct ldp_igp_sync_if_state *state)
{
	debug_evt_ldp_sync("LDP_DBG_SYNC: %s: name=%s, ifindex=%d, sync_start=%d",
		__func__, state->name, state->ifindex, state->sync_start);

        return zclient_send_opaque(zclient, LDP_IGP_SYNC_IF_STATE_UPDATE,
		(const uint8_t *) state, sizeof(*state));
}

int ldp_sync_send_announce_update(struct ldp_igp_sync_if_announce *announce)
{
	debug_evt_ldp_sync("LDP_DBG_SYNC: %s: name=%s, ifindex=%d",
		__func__, announce->name, announce->ifindex);

        return zclient_send_opaque(zclient, LDP_IGP_SYNC_IF_STATE_UPDATE,
		(const uint8_t *) announce, sizeof(*announce));
}

static int ldp_zebra_opaque_msg_handler(ZAPI_CALLBACK_ARGS)
{
	uint32_t type;
	struct ldp_igp_sync_if_config config;
	struct stream *s;

	s = zclient->ibuf;

	STREAM_GETL(s, type);

	switch (type) {
	case LDP_IGP_SYNC_IF_CONFIG_UPDATE:
                STREAM_GET(&config, s, sizeof(config));
		main_imsg_compose_ldpe(IMSG_LDP_SYNC_IF_CONFIG_UPDATE, 0, &config,
			    sizeof(config));
		break;
	default:
		break;
	}

stream_failure:

        return 0;
}

static int
ldp_zebra_send_mpls_labels(int cmd, struct kroute *kr)
{
	struct zapi_labels zl = {};
	struct zapi_nexthop *znh;

	if (kr->local_label < MPLS_LABEL_RESERVED_MAX)
		return (0);

	debug_zebra_out("prefix %s/%u nexthop %s ifindex %u labels %s/%s (%s)",
	    log_addr(kr->af, &kr->prefix), kr->prefixlen,
	    log_addr(kr->af, &kr->nexthop), kr->ifindex,
	    log_label(kr->local_label), log_label(kr->remote_label),
	    (cmd == ZEBRA_MPLS_LABELS_ADD) ? "add" : "delete");

	zl.type = ZEBRA_LSP_LDP;
	zl.local_label = kr->local_label;

	/* Set prefix. */
	if (kr->remote_label != NO_LABEL) {
		SET_FLAG(zl.message, ZAPI_LABELS_FTN);
		zl.route.prefix.family = kr->af;
		switch (kr->af) {
		case AF_INET:
			zl.route.prefix.u.prefix4 = kr->prefix.v4;
			break;
		case AF_INET6:
			zl.route.prefix.u.prefix6 = kr->prefix.v6;
			break;
		default:
			fatalx("ldp_zebra_send_mpls_labels: unknown af");
		}
		zl.route.prefix.prefixlen = kr->prefixlen;
		zl.route.type = kr->route_type;
		zl.route.instance = kr->route_instance;
	}

	/*
	 * For broken LSPs, instruct the forwarding plane to pop the top-level
	 * label and forward packets normally. This is a best-effort attempt
	 * to deliver labeled IP packets to their final destination (instead of
	 * dropping them).
	 */
	if (kr->remote_label == NO_LABEL)
		kr->remote_label = MPLS_LABEL_IMPLICIT_NULL;

	/* Set nexthop. */
	zl.nexthop_num = 1;
	znh = &zl.nexthops[0];
	switch (kr->af) {
	case AF_INET:
		znh->gate.ipv4 = kr->nexthop.v4;
		if (kr->ifindex)
			znh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
		else
			znh->type = NEXTHOP_TYPE_IPV4;
		break;
	case AF_INET6:
		znh->gate.ipv6 = kr->nexthop.v6;
		if (kr->ifindex)
			znh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
		else
			znh->type = NEXTHOP_TYPE_IPV6;
		break;
	default:
		break;
	}
	znh->ifindex = kr->ifindex;
	znh->label_num = 1;
	znh->labels[0] = kr->remote_label;

	return zebra_send_mpls_labels(zclient, cmd, &zl);
}

int
kr_change(struct kroute *kr)
{
	return (ldp_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_ADD, kr));
}

int
kr_delete(struct kroute *kr)
{
	return (ldp_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_DELETE, kr));
}

int
kmpw_add(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (add)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return (zebra_send_pw(zclient, ZEBRA_PW_ADD, zpw));
}

int
kmpw_del(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (del)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return (zebra_send_pw(zclient, ZEBRA_PW_DELETE, zpw));
}

int
kmpw_set(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s labels %u/%u (set)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop),
	    zpw->local_label, zpw->remote_label);

	return (zebra_send_pw(zclient, ZEBRA_PW_SET, zpw));
}

int
kmpw_unset(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (unset)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return (zebra_send_pw(zclient, ZEBRA_PW_UNSET, zpw));
}

void
kif_redistribute(const char *ifname)
{
	struct vrf		*vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct listnode		*cnode;
	struct interface	*ifp;
	struct connected	*ifc;
	struct kif		 kif;
	struct kaddr		 ka;

	FOR_ALL_INTERFACES (vrf, ifp) {
		if (ifname && strcmp(ifname, ifp->name) != 0)
			continue;

		ifp2kif(ifp, &kif);
		main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka,
			    sizeof(ka));
		}
	}
}

static int
ldp_router_id_update(ZAPI_CALLBACK_ARGS)
{
	struct prefix	 router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	if (bad_addr_v4(router_id.u.prefix4))
		return (0);

	debug_zebra_in("router-id update %s", inet_ntoa(router_id.u.prefix4));

	global.rtr_id.s_addr = router_id.u.prefix4.s_addr;
	main_imsg_compose_ldpe(IMSG_RTRID_UPDATE, 0, &global.rtr_id,
	    sizeof(global.rtr_id));

	return (0);
}

static int
ldp_ifp_create(struct interface *ifp)
{
	struct kif		 kif;

	debug_zebra_in("interface add %s index %d mtu %d", ifp->name,
	    ifp->ifindex, ifp->mtu);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	return 0;
}

static int
ldp_ifp_destroy(struct interface *ifp)
{
	struct kif		 kif;

	debug_zebra_in("interface delete %s index %d mtu %d", ifp->name,
	    ifp->ifindex, ifp->mtu);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	return (0);
}

static int
ldp_interface_status_change_helper(struct interface *ifp)
{
	struct listnode		*node;
	struct connected	*ifc;
	struct kif		 kif;
	struct kaddr		 ka;

	debug_zebra_in("interface %s state update", ifp->name);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	if (if_is_operative(ifp)) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka,
			    sizeof(ka));
		}
	} else {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_DELADDR, 0, &ka,
			    sizeof(ka));
		}
	}

	return (0);
}

static int ldp_ifp_up(struct interface *ifp)
{
	return ldp_interface_status_change_helper(ifp);
}

static int ldp_ifp_down(struct interface *ifp)
{
	return ldp_interface_status_change_helper(ifp);
}

static int
ldp_interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected	*ifc;
	struct interface	*ifp;
	struct kaddr		 ka;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return (0);

	ifp = ifc->ifp;
	ifc2kaddr(ifp, ifc, &ka);

	/* Filter invalid addresses.  */
	if (bad_addr(ka.af, &ka.addr))
		return (0);

	debug_zebra_in("address add %s/%u interface %s",
	    log_addr(ka.af, &ka.addr), ka.prefixlen, ifp->name);

	/* notify ldpe about new address */
	main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka, sizeof(ka));

	return (0);
}

static int
ldp_interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected	*ifc;
	struct interface	*ifp;
	struct kaddr		 ka;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return (0);

	ifp = ifc->ifp;
	ifc2kaddr(ifp, ifc, &ka);
	connected_free(&ifc);

	/* Filter invalid addresses.  */
	if (bad_addr(ka.af, &ka.addr))
		return (0);

	debug_zebra_in("address delete %s/%u interface %s",
	    log_addr(ka.af, &ka.addr), ka.prefixlen, ifp->name);

	/* notify ldpe about removed address */
	main_imsg_compose_ldpe(IMSG_DELADDR, 0, &ka, sizeof(ka));

	return (0);
}

static int
ldp_zebra_read_route(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route	 api;
	struct zapi_nexthop	*api_nh;
	struct kroute		 kr;
	int			 i, add = 0;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return (0);

	memset(&kr, 0, sizeof(kr));
	kr.af = api.prefix.family;
	switch (kr.af) {
	case AF_INET:
		kr.prefix.v4 = api.prefix.u.prefix4;
		break;
	case AF_INET6:
		kr.prefix.v6 = api.prefix.u.prefix6;
		break;
	default:
		break;
	}
	kr.prefixlen = api.prefix.prefixlen;
	kr.route_type = api.type;
	kr.route_instance = api.instance;

	switch (api.type) {
	case ZEBRA_ROUTE_CONNECT:
		kr.flags |= F_CONNECTED;
		break;
	case ZEBRA_ROUTE_BGP:
		/* LDP should follow the IGP and ignore BGP routes */
		return (0);
	default:
		break;
	}

	if (bad_addr(kr.af, &kr.prefix) ||
	    (kr.af == AF_INET6 && IN6_IS_SCOPE_EMBED(&kr.prefix.v6)))
		return (0);

	if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		add = 1;

	if (api.nexthop_num == 0)
		debug_zebra_in("route %s %s/%d (%s)", (add) ? "add" : "delete",
		    log_addr(kr.af, &kr.prefix), kr.prefixlen,
		    zebra_route_string(api.type));

	/* loop through all the nexthops */
	for (i = 0; i < api.nexthop_num; i++) {
		api_nh = &api.nexthops[i];
		switch (api_nh->type) {
		case NEXTHOP_TYPE_IPV4:
			if (kr.af != AF_INET)
				continue;
			kr.nexthop.v4 = api_nh->gate.ipv4;
			kr.ifindex = 0;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			if (kr.af != AF_INET)
				continue;
			kr.nexthop.v4 = api_nh->gate.ipv4;
			kr.ifindex = api_nh->ifindex;
			break;
		case NEXTHOP_TYPE_IPV6:
			if (kr.af != AF_INET6)
				continue;
			kr.nexthop.v6 = api_nh->gate.ipv6;
			kr.ifindex = 0;
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			if (kr.af != AF_INET6)
				continue;
			kr.nexthop.v6 = api_nh->gate.ipv6;
			kr.ifindex = api_nh->ifindex;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			if (!(kr.flags & F_CONNECTED))
				continue;
			break;
		default:
			continue;
		}

		debug_zebra_in("route %s %s/%d nexthop %s ifindex %u (%s)",
		    (add) ? "add" : "delete", log_addr(kr.af, &kr.prefix),
		    kr.prefixlen, log_addr(kr.af, &kr.nexthop), kr.ifindex,
		    zebra_route_string(api.type));

		if (add)
			main_imsg_compose_lde(IMSG_NETWORK_ADD, 0, &kr,
			    sizeof(kr));
	}

	main_imsg_compose_lde(IMSG_NETWORK_UPDATE, 0, &kr, sizeof(kr));

	return (0);
}

/*
 * Receive PW status update from Zebra and send it to LDE process.
 */
static int
ldp_zebra_read_pw_status_update(ZAPI_CALLBACK_ARGS)
{
	struct zapi_pw_status	 zpw;

	zebra_read_pw_status_update(cmd, zclient, length, vrf_id, &zpw);

	debug_zebra_in("pseudowire %s status %s 0x%x", zpw.ifname,
	    (zpw.status == PW_FORWARDING) ? "up" : "down",
	    zpw.status);

	main_imsg_compose_lde(IMSG_PW_UPDATE, 0, &zpw, sizeof(zpw));

	return (0);
}

static void
ldp_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP,
	    ZEBRA_ROUTE_ALL, 0, VRF_DEFAULT);
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6,
	    ZEBRA_ROUTE_ALL, 0, VRF_DEFAULT);

	ldp_zebra_opaque_register();
}

static void
ldp_zebra_filter_update(struct access_list *access)
{
	struct ldp_access laccess;

	if (access && access->name[0] != '\0') {
		strlcpy(laccess.name, access->name, sizeof(laccess.name));
		laccess.type = access->type;
		debug_evt("%s ACL update filter name %s type %d", __func__,
		    access->name, access->type);

		main_imsg_compose_both(IMSG_FILTER_UPDATE, &laccess,
			sizeof(laccess));
	}
}

extern struct zebra_privs_t ldpd_privs;

void
ldp_zebra_init(struct thread_master *master)
{
	if_zapi_callbacks(ldp_ifp_create, ldp_ifp_up,
			  ldp_ifp_down, ldp_ifp_destroy);

	/* Set default values. */
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_LDP, 0, &ldpd_privs);

	/* set callbacks */
	zclient->zebra_connected = ldp_zebra_connected;
	zclient->router_id_update = ldp_router_id_update;
	zclient->interface_address_add = ldp_interface_address_add;
	zclient->interface_address_delete = ldp_interface_address_delete;
	zclient->redistribute_route_add = ldp_zebra_read_route;
	zclient->redistribute_route_del = ldp_zebra_read_route;
	zclient->pw_status_update = ldp_zebra_read_pw_status_update;
	zclient->opaque_msg_handler = ldp_zebra_opaque_msg_handler;

	/* Access list initialize. */
	access_list_add_hook(ldp_zebra_filter_update);
	access_list_delete_hook(ldp_zebra_filter_update);
}

void
ldp_zebra_destroy(void)
{
	ldp_zebra_opaque_unregister();
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient = NULL;
}
