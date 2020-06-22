/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005, 2008 Esben Norby <norby@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "log.h"
#include "ldp_debug.h"

#include "sockopt.h"

static __inline int	 iface_compare(const struct iface *, const struct iface *);
static struct if_addr	*if_addr_new(struct kaddr *);
static struct if_addr	*if_addr_lookup(struct if_addr_head *, struct kaddr *);
static int		 if_start(struct iface *, int);
static int		 if_reset(struct iface *, int);
static void		 if_update_af(struct iface_af *);
static int		 if_hello_timer(struct thread *);
static void		 if_start_hello_timer(struct iface_af *);
static void		 if_stop_hello_timer(struct iface_af *);
static int		 if_join_ipv4_group(struct iface *, struct in_addr *);
static int		 if_leave_ipv4_group(struct iface *, struct in_addr *);
static int		 if_join_ipv6_group(struct iface *, struct in6_addr *);
static int		 if_leave_ipv6_group(struct iface *, struct in6_addr *);

static int ldp_sync_fsm_init(struct iface *iface, int state);
static int ldp_sync_act_iface_start_sync(struct iface *iface);
static int iface_wait_for_ldp_sync_timer(struct thread *thread);
static void start_wait_for_ldp_sync_timer(struct iface *iface);
static void stop_wait_for_ldp_sync_timer(struct iface *iface);
static int ldp_sync_act_ldp_start_sync(struct iface *iface);
static int ldp_sync_act_ldp_complete_sync(struct iface *iface);
static struct iface *nbr_to_hello_link_iface(struct nbr *nbr, int *nbr_count);

RB_GENERATE(iface_head, iface, entry, iface_compare)

static __inline int
iface_compare(const struct iface *a, const struct iface *b)
{
	return if_cmp_name_func(a->name, b->name);
}

struct iface *
if_new(const char *name)
{
	struct iface		*iface;

	if ((iface = calloc(1, sizeof(*iface))) == NULL)
		fatal("if_new: calloc");

	strlcpy(iface->name, name, sizeof(iface->name));

	/* ipv4 */
	iface->ipv4.af = AF_INET;
	iface->ipv4.iface = iface;
	iface->ipv4.enabled = 0;

	/* ipv6 */
	iface->ipv6.af = AF_INET6;
	iface->ipv6.iface = iface;
	iface->ipv6.enabled = 0;

	return (iface);
}

void
ldpe_if_init(struct iface *iface)
{
	log_debug("%s: interface %s", __func__, iface->name);

	LIST_INIT(&iface->addr_list);

	/* ipv4 */
	iface->ipv4.iface = iface;
	iface->ipv4.state = IF_STA_DOWN;
	RB_INIT(ia_adj_head, &iface->ipv4.adj_tree);

	/* ipv6 */
	iface->ipv6.iface = iface;
	iface->ipv6.state = IF_STA_DOWN;
	RB_INIT(ia_adj_head, &iface->ipv6.adj_tree);

	/* LGP IGP Sync */
	ldp_sync_fsm_init(iface, LDP_SYNC_STA_REQ_NOT_ACH);
}

void
ldpe_if_exit(struct iface *iface)
{
	struct if_addr		*if_addr;

	log_debug("%s: interface %s", __func__, iface->name);

	ldp_sync_fsm(iface, LDP_SYNC_EVT_CONFIG_LDP_OFF);

	if (iface->ipv4.state == IF_STA_ACTIVE)
		if_reset(iface, AF_INET);
	if (iface->ipv6.state == IF_STA_ACTIVE)
		if_reset(iface, AF_INET6);

	while ((if_addr = LIST_FIRST(&iface->addr_list)) != NULL) {
		LIST_REMOVE(if_addr, entry);
		assert(if_addr != LIST_FIRST(&iface->addr_list));
		free(if_addr);
	}
}

struct iface *
if_lookup(struct ldpd_conf *xconf, ifindex_t ifindex)
{
	struct iface *iface;

	RB_FOREACH(iface, iface_head, &xconf->iface_tree)
		if (iface->ifindex == ifindex)
			return (iface);

	return (NULL);
}

struct iface *
if_lookup_name(struct ldpd_conf *xconf, const char *ifname)
{
	struct iface     iface;
	strlcpy(iface.name, ifname, sizeof(iface.name));
	return (RB_FIND(iface_head, &xconf->iface_tree, &iface));
}

void
if_update_info(struct iface *iface, struct kif *kif)
{
	/* get type */
	if (kif->flags & IFF_POINTOPOINT)
		iface->type = IF_TYPE_POINTOPOINT;
	if (kif->flags & IFF_BROADCAST &&
	    kif->flags & IFF_MULTICAST)
		iface->type = IF_TYPE_BROADCAST;

	if (ldpd_process == PROC_LDP_ENGINE && iface->operative && !kif->operative)
		ldp_sync_fsm(iface, LDP_SYNC_EVT_IFACE_SHUTDOWN);

	int old_ifindex = iface->ifindex;

	/* get index and flags */
	iface->ifindex = kif->ifindex;
	iface->operative = kif->operative;

	if (ldpd_process == PROC_LDP_ENGINE &&
	    old_ifindex == 0 &&
	    old_ifindex != iface->ifindex)
		ldp_sync_fsm(iface, LDP_SYNC_EVT_IFACE_ANNOUNCE);
// TODO: if new interface is added to LDP should we send a 'not in sync' event?
}

struct iface_af *
iface_af_get(struct iface *iface, int af)
{
	switch (af) {
	case AF_INET:
		return (&iface->ipv4);
	case AF_INET6:
		return (&iface->ipv6);
	default:
		fatalx("iface_af_get: unknown af");
	}
}

static struct if_addr *
if_addr_new(struct kaddr *ka)
{
	struct if_addr	*if_addr;

	if ((if_addr = calloc(1, sizeof(*if_addr))) == NULL)
		fatal(__func__);

	if_addr->af = ka->af;
	if_addr->addr = ka->addr;
	if_addr->prefixlen = ka->prefixlen;
	if_addr->dstbrd = ka->dstbrd;

	return (if_addr);
}

static struct if_addr *
if_addr_lookup(struct if_addr_head *addr_list, struct kaddr *ka)
{
	struct if_addr	*if_addr;
	int		 af = ka->af;

	LIST_FOREACH(if_addr, addr_list, entry)
		if (!ldp_addrcmp(af, &if_addr->addr, &ka->addr) &&
		    if_addr->prefixlen == ka->prefixlen &&
		    !ldp_addrcmp(af, &if_addr->dstbrd, &ka->dstbrd))
			return (if_addr);

	return (NULL);
}

void
if_addr_add(struct kaddr *ka)
{
	struct iface		*iface;
	struct if_addr		*if_addr;
	struct nbr		*nbr;

	if (if_addr_lookup(&global.addr_list, ka) == NULL) {
		if_addr = if_addr_new(ka);

		LIST_INSERT_HEAD(&global.addr_list, if_addr, entry);
		RB_FOREACH(nbr, nbr_id_head, &nbrs_by_id) {
			if (nbr->state != NBR_STA_OPER)
				continue;
			if (if_addr->af == AF_INET && !nbr->v4_enabled)
				continue;
			if (if_addr->af == AF_INET6 && !nbr->v6_enabled)
				continue;

			send_address_single(nbr, if_addr, 0);
		}
	}

	iface = if_lookup_name(leconf, ka->ifname);
	if (iface) {
		if (ka->af == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&ka->addr.v6))
			iface->linklocal = ka->addr.v6;

		if (if_addr_lookup(&iface->addr_list, ka) == NULL) {
			if_addr = if_addr_new(ka);
			LIST_INSERT_HEAD(&iface->addr_list, if_addr, entry);
			ldp_if_update(iface, if_addr->af);
		}
	}
}

void
if_addr_del(struct kaddr *ka)
{
	struct iface		*iface;
	struct if_addr		*if_addr;
	struct nbr		*nbr;

	iface = if_lookup_name(leconf, ka->ifname);
	if (iface) {
		if (ka->af == AF_INET6 &&
		    IN6_ARE_ADDR_EQUAL(&iface->linklocal, &ka->addr.v6))
			memset(&iface->linklocal, 0, sizeof(iface->linklocal));

		if_addr = if_addr_lookup(&iface->addr_list, ka);
		if (if_addr) {
			LIST_REMOVE(if_addr, entry);
			ldp_if_update(iface, if_addr->af);
			free(if_addr);
		}
	}

	if_addr = if_addr_lookup(&global.addr_list, ka);
	if (if_addr) {
		RB_FOREACH(nbr, nbr_id_head, &nbrs_by_id) {
			if (nbr->state != NBR_STA_OPER)
				continue;
			if (if_addr->af == AF_INET && !nbr->v4_enabled)
				continue;
			if (if_addr->af == AF_INET6 && !nbr->v6_enabled)
				continue;
			send_address_single(nbr, if_addr, 1);
		}
		LIST_REMOVE(if_addr, entry);
		free(if_addr);
	}
}

static int
if_start(struct iface *iface, int af)
{
	struct iface_af		*ia;
	struct timeval		 now;

	log_debug("%s: %s address-family %s", __func__, iface->name,
	    af_name(af));

	ia = iface_af_get(iface, af);

	gettimeofday(&now, NULL);
	ia->uptime = now.tv_sec;

	switch (af) {
	case AF_INET:
		if (if_join_ipv4_group(iface, &global.mcast_addr_v4))
			return (-1);
		break;
	case AF_INET6:
		if (if_join_ipv6_group(iface, &global.mcast_addr_v6))
			return (-1);
		break;
	default:
		fatalx("if_start: unknown af");
	}

	send_hello(HELLO_LINK, ia, NULL);
	if_start_hello_timer(ia);
	ia->state = IF_STA_ACTIVE;

	return (0);
}

static int
if_reset(struct iface *iface, int af)
{
	struct iface_af		*ia;
	struct adj		*adj;

	log_debug("%s: %s address-family %s", __func__, iface->name,
	    af_name(af));

	ia = iface_af_get(iface, af);
	if_stop_hello_timer(ia);

	while (!RB_EMPTY(ia_adj_head, &ia->adj_tree)) {
		adj = RB_ROOT(ia_adj_head, &ia->adj_tree);

		adj_del(adj, S_SHUTDOWN);
	}

	/* try to cleanup */
	switch (af) {
	case AF_INET:
		if (global.ipv4.ldp_disc_socket != -1)
			if_leave_ipv4_group(iface, &global.mcast_addr_v4);
		break;
	case AF_INET6:
		if (global.ipv6.ldp_disc_socket != -1)
			if_leave_ipv6_group(iface, &global.mcast_addr_v6);
		break;
	default:
		fatalx("if_reset: unknown af");
	}

	ia->state = IF_STA_DOWN;

	return (0);
}

static void
if_update_af(struct iface_af *ia)
{
	int			 addr_ok = 0, socket_ok, rtr_id_ok;
	struct if_addr		*if_addr;

	switch (ia->af) {
	case AF_INET:
		/*
		 * NOTE: for LDPv4, each interface should have at least one
		 * valid IP address otherwise they can not be enabled.
		 */
		LIST_FOREACH(if_addr, &ia->iface->addr_list, entry) {
			if (if_addr->af == AF_INET) {
				addr_ok = 1;
				break;
			}
		}
		break;
	case AF_INET6:
		/* for IPv6 the link-local address is enough. */
		if (IN6_IS_ADDR_LINKLOCAL(&ia->iface->linklocal))
			addr_ok = 1;
		break;
	default:
		fatalx("if_update_af: unknown af");
	}

	if ((ldp_af_global_get(&global, ia->af))->ldp_disc_socket != -1)
		socket_ok = 1;
	else
		socket_ok = 0;

	if (ldp_rtr_id_get(leconf) != INADDR_ANY)
		rtr_id_ok = 1;
	else
		rtr_id_ok = 0;

	if (ia->state == IF_STA_DOWN) {
		if (!ia->enabled || !ia->iface->operative || !addr_ok ||
		    !socket_ok || !rtr_id_ok)
			return;

		if_start(ia->iface, ia->af);
	} else if (ia->state == IF_STA_ACTIVE) {
		if (ia->enabled && ia->iface->operative && addr_ok &&
		    socket_ok && rtr_id_ok)
			return;

		if_reset(ia->iface, ia->af);
	}
}

void
ldp_if_update(struct iface *iface, int af)
{
	if (af == AF_INET || af == AF_UNSPEC)
		if_update_af(&iface->ipv4);
	if (af == AF_INET6 || af == AF_UNSPEC)
		if_update_af(&iface->ipv6);
}

void
if_update_all(int af)
{
	struct iface		*iface;

	RB_FOREACH(iface, iface_head, &leconf->iface_tree)
		ldp_if_update(iface, af);
}

uint16_t
if_get_hello_holdtime(struct iface_af *ia)
{
	if (ia->hello_holdtime != 0)
		return (ia->hello_holdtime);

	if ((ldp_af_conf_get(leconf, ia->af))->lhello_holdtime != 0)
		return ((ldp_af_conf_get(leconf, ia->af))->lhello_holdtime);

	return (leconf->lhello_holdtime);
}

uint16_t
if_get_hello_interval(struct iface_af *ia)
{
	if (ia->hello_interval != 0)
		return (ia->hello_interval);

	if ((ldp_af_conf_get(leconf, ia->af))->lhello_interval != 0)
		return ((ldp_af_conf_get(leconf, ia->af))->lhello_interval);

	return (leconf->lhello_interval);
}

uint16_t
if_get_wait_for_sync_interval(void)
{
	return (leconf->wait_for_sync_interval);
}

/* timers */
/* ARGSUSED */
static int
if_hello_timer(struct thread *thread)
{
	struct iface_af		*ia = THREAD_ARG(thread);

	ia->hello_timer = NULL;
	send_hello(HELLO_LINK, ia, NULL);
	if_start_hello_timer(ia);

	return (0);
}

static void
if_start_hello_timer(struct iface_af *ia)
{
	THREAD_TIMER_OFF(ia->hello_timer);
	ia->hello_timer = NULL;
	thread_add_timer(master, if_hello_timer, ia, if_get_hello_interval(ia),
			 &ia->hello_timer);
}

static void
if_stop_hello_timer(struct iface_af *ia)
{
	THREAD_TIMER_OFF(ia->hello_timer);
}

struct ctl_iface *
if_to_ctl(struct iface_af *ia)
{
	static struct ctl_iface	 ictl;
	struct timeval		 now;
	struct adj		*adj;

	ictl.af = ia->af;
	memcpy(ictl.name, ia->iface->name, sizeof(ictl.name));
	ictl.ifindex = ia->iface->ifindex;
	ictl.state = ia->state;
	ictl.type = ia->iface->type;
	ictl.hello_holdtime = if_get_hello_holdtime(ia);
	ictl.hello_interval = if_get_hello_interval(ia);

	gettimeofday(&now, NULL);
	if (ia->state != IF_STA_DOWN &&
	    ia->uptime != 0) {
		ictl.uptime = now.tv_sec - ia->uptime;
	} else
		ictl.uptime = 0;

	ictl.adj_cnt = 0;
	RB_FOREACH(adj, ia_adj_head, &ia->adj_tree)
		ictl.adj_cnt++;

	return (&ictl);
}

/* multicast membership sockopts */
in_addr_t
if_get_ipv4_addr(struct iface *iface)
{
	struct if_addr		*if_addr;

	LIST_FOREACH(if_addr, &iface->addr_list, entry)
		if (if_addr->af == AF_INET)
			return (if_addr->addr.v4.s_addr);

	return (INADDR_ANY);
}

static int
if_join_ipv4_group(struct iface *iface, struct in_addr *addr)
{
	struct in_addr		 if_addr;

	log_debug("%s: interface %s addr %s", __func__, iface->name,
	    inet_ntoa(*addr));

	if_addr.s_addr = if_get_ipv4_addr(iface);

	if (setsockopt_ipv4_multicast(global.ipv4.ldp_disc_socket,
	    IP_ADD_MEMBERSHIP, if_addr, addr->s_addr, iface->ifindex) < 0) {
		log_warn("%s: error IP_ADD_MEMBERSHIP, interface %s address %s",
		     __func__, iface->name, inet_ntoa(*addr));
		return (-1);
	}
	return (0);
}

static int
if_leave_ipv4_group(struct iface *iface, struct in_addr *addr)
{
	struct in_addr		 if_addr;

	log_debug("%s: interface %s addr %s", __func__, iface->name,
	    inet_ntoa(*addr));

	if_addr.s_addr = if_get_ipv4_addr(iface);

	if (setsockopt_ipv4_multicast(global.ipv4.ldp_disc_socket,
	    IP_DROP_MEMBERSHIP, if_addr, addr->s_addr, iface->ifindex) < 0) {
		log_warn("%s: error IP_DROP_MEMBERSHIP, interface %s "
		    "address %s", __func__, iface->name, inet_ntoa(*addr));
		return (-1);
	}

	return (0);
}

static int
if_join_ipv6_group(struct iface *iface, struct in6_addr *addr)
{
	struct ipv6_mreq	 mreq;

	log_debug("%s: interface %s addr %s", __func__, iface->name,
	    log_in6addr(addr));

	mreq.ipv6mr_multiaddr = *addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (setsockopt(global.ipv6.ldp_disc_socket, IPPROTO_IPV6,
	    IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
		log_warn("%s: error IPV6_JOIN_GROUP, interface %s address %s",
		    __func__, iface->name, log_in6addr(addr));
		return (-1);
	}

	return (0);
}

static int
if_leave_ipv6_group(struct iface *iface, struct in6_addr *addr)
{
	struct ipv6_mreq	 mreq;

	log_debug("%s: interface %s addr %s", __func__, iface->name,
	    log_in6addr(addr));

	mreq.ipv6mr_multiaddr = *addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (setsockopt(global.ipv6.ldp_disc_socket, IPPROTO_IPV6,
	    IPV6_LEAVE_GROUP, (void *)&mreq, sizeof(mreq)) < 0) {
		log_warn("%s: error IPV6_LEAVE_GROUP, interface %s address %s",
		    __func__, iface->name, log_in6addr(addr));
		return (-1);
	}

	return (0);
}

const struct {
	int				state;
	enum ldp_sync_event		event;
	enum ldp_sync_action		action;
	int				new_state;
} ldp_sync_fsm_tbl[] = {
    /* current state		event that happened		action to take			resulting state */
/* LDP IGP Sync required not achieved */
    {LDP_SYNC_STA_REQ_NOT_ACH,	LDP_SYNC_EVT_LDP_SYNC_START, 	LDP_SYNC_ACT_LDP_START_SYNC,	0},
    {LDP_SYNC_STA_REQ_NOT_ACH,	LDP_SYNC_EVT_LDP_SYNC_COMPLETE,	LDP_SYNC_ACT_LDP_COMPLETE_SYNC,	LDP_SYNC_STA_REQ_ACH},
    {LDP_SYNC_STA_REQ_NOT_ACH,	LDP_SYNC_EVT_CONFIG_LDP_OFF,	LDP_SYNC_ACT_CONFIG_LDP_OFF,	LDP_SYNC_STA_REQ_NOT_ACH},
    {LDP_SYNC_STA_REQ_NOT_ACH,	LDP_SYNC_EVT_IFACE_SHUTDOWN, 	LDP_SYNC_ACT_IFACE_SHUTDOWN,	LDP_SYNC_STA_REQ_NOT_ACH},
    {LDP_SYNC_STA_REQ_NOT_ACH,	LDP_SYNC_EVT_SESSION_CLOSE, 	LDP_SYNC_ACT_NOTHING,		0},
    {LDP_SYNC_STA_REQ_NOT_ACH,	LDP_SYNC_EVT_ADJ_DEL, 		LDP_SYNC_ACT_NOTHING,		0},
    {LDP_SYNC_STA_REQ_NOT_ACH,	LDP_SYNC_EVT_ADJ_NEW, 		LDP_SYNC_ACT_NOTHING,		0},
/* LDP IGP Sync required achieved */
    {LDP_SYNC_STA_REQ_ACH,	LDP_SYNC_EVT_CONFIG_LDP_OFF,	LDP_SYNC_ACT_CONFIG_LDP_OFF,	LDP_SYNC_STA_REQ_NOT_ACH},
    {LDP_SYNC_STA_REQ_ACH,	LDP_SYNC_EVT_LDP_SYNC_COMPLETE,	LDP_SYNC_ACT_NOTHING,		0},
    {LDP_SYNC_STA_REQ_ACH,	LDP_SYNC_EVT_LDP_SYNC_START, 	LDP_SYNC_ACT_NOTHING,		0},
    {LDP_SYNC_STA_REQ_ACH,	LDP_SYNC_EVT_IFACE_SHUTDOWN, 	LDP_SYNC_ACT_IFACE_SHUTDOWN,	LDP_SYNC_STA_REQ_NOT_ACH},
    {LDP_SYNC_STA_REQ_ACH,	LDP_SYNC_EVT_SESSION_CLOSE, 	LDP_SYNC_ACT_IFACE_START_SYNC,	LDP_SYNC_STA_REQ_NOT_ACH},
    {LDP_SYNC_STA_REQ_ACH,	LDP_SYNC_EVT_ADJ_DEL, 		LDP_SYNC_ACT_IFACE_START_SYNC,	LDP_SYNC_STA_REQ_NOT_ACH},
    {LDP_SYNC_STA_REQ_ACH,	LDP_SYNC_EVT_ADJ_NEW, 		LDP_SYNC_ACT_NOTHING,		0},
    {-1,			LDP_SYNC_EVT_NOTHING,		LDP_SYNC_ACT_NOTHING,		0},
};

const char * const ldp_sync_event_names[] = {
	"NOTHING",
	"LDP SYNC START",
	"LDP SYNC COMPLETE",
	"CONFIG LDP OFF",
	"IFACE SYNC START (ADJ DEL)",
	"IFACE SYNC START (ADJ NEW)",
	"IFACE SYNC START (SESSION CLOSE)",
	"IFACE SYNC START (CONFIG LDP ON)",
	"IFACE ANNOUNCE",
	"IFACE SHUTDOWN",
	"N/A"
};

const char * const ldp_sync_action_names[] = {
	"NOTHING",
	"IFACE SYNC START",
	"LDP START SYNC",
	"LDP COMPLETE SYNC",
	"CONFIG LDP OFF",
	"IFACE ANNOUNCE",
	"IFACE SHUTDOWN",
	"N/A"
};

const char *
ldp_sync_state_name(int state)
{
	switch (state) {
	case LDP_SYNC_STA_REQ_NOT_ACH:
		return ("REQUIRED NOT ACHIEVED");
	case LDP_SYNC_STA_REQ_ACH:
		return ("REQUIRED ACHIEVED");
	default:
		return ("UNKNOWN");
	}
}

static int
send_ldp_sync_state_update_msg(char *name, int ifindex, int sync_start)
{
	debug_evt_ldp_sync("%s: interface %s, ifindex=%d, sync_start=%d",
		    __func__, name, ifindex, sync_start);

	struct ldp_igp_sync_if_state state;

	strlcpy(state.name, name, sizeof(state.name));
	state.ifindex = ifindex;
	state.sync_start = sync_start;

	return ldpe_imsg_compose_parent(IMSG_LDP_SYNC_IF_STATE_UPDATE, getpid(),
		&state, sizeof(state));
}

static int
ldp_sync_act_iface_start_sync(struct iface *iface)
{
	debug_evt_ldp_sync("%s: interface %s",
		    __func__, iface->name);

	send_ldp_sync_state_update_msg(iface->name, iface->ifindex, true);

	return (0);
}

static int
iface_wait_for_ldp_sync_timer(struct thread *thread)
{
	struct iface *iface = THREAD_ARG(thread);

	debug_evt_ldp_sync("%s: interface %s",
		    __func__, iface->name);

	ldp_sync_fsm(iface, LDP_SYNC_EVT_LDP_SYNC_COMPLETE);

	return (0);
}

static void start_wait_for_ldp_sync_timer(struct iface *iface)
{
	debug_evt_ldp_sync("%s: interface %s",
		    __func__, iface->name);

	THREAD_TIMER_OFF(iface->ldp_sync.wait_for_ldp_sync_timer);
	iface->ldp_sync.wait_for_ldp_sync_timer = NULL;
	thread_add_timer(master, iface_wait_for_ldp_sync_timer, iface,
			if_get_wait_for_sync_interval(),
			&iface->ldp_sync.wait_for_ldp_sync_timer);
}

static void stop_wait_for_ldp_sync_timer(struct iface *iface)
{
	debug_evt_ldp_sync("%s: interface %s",
		    __func__, iface->name);

	THREAD_TIMER_OFF(iface->ldp_sync.wait_for_ldp_sync_timer);
	iface->ldp_sync.wait_for_ldp_sync_timer = NULL;
}

static int
ldp_sync_act_ldp_start_sync(struct iface *iface)
{
	debug_evt_ldp_sync("%s: interface %s",
		    __func__, iface->name);

	start_wait_for_ldp_sync_timer(iface);

	return 0;
}

static int
ldp_sync_act_ldp_complete_sync(struct iface *iface)
{
	debug_evt_ldp_sync("%s: interface %s",
		    __func__, iface->name);

	send_ldp_sync_state_update_msg(iface->name, iface->ifindex, false);

	return 0;
}

static struct iface *
nbr_to_hello_link_iface(struct nbr *nbr, int *nbr_count)
{
	struct adj      *adj;
	struct iface 	*iface = NULL;
	*nbr_count = 0;
	RB_FOREACH(adj, nbr_adj_head, &nbr->adj_tree)
	{
		if (HELLO_LINK == adj->source.type) {
			if (!iface)
				iface = adj->source.link.ia->iface;

			(*nbr_count)++;
		}
	}

	return iface;
}

int
ldp_sync_fsm_helper_adj(struct adj *adj, enum ldp_sync_event event)
{
        if (HELLO_LINK != adj->source.type)
		return -1;

	debug_evt_ldp_sync("%s: adj iface %s, event %s (%d)",
		    __func__, adj->source.link.ia->iface->name,
		    ldp_sync_event_names[event], event);

	struct iface *iface = adj->source.link.ia->iface;

	if (!iface->operative)
		return 0;

	return ldp_sync_fsm(iface, event);
}

int
ldp_sync_fsm_helper_nbr(struct nbr *nbr, enum ldp_sync_event event)
{
	debug_evt_ldp_sync("%s: lsr-id %s, event %s (%d)",
		    __func__, inet_ntoa(nbr->id),
		    ldp_sync_event_names[event], event);

	int nbr_count = 0;
	struct iface *iface = nbr_to_hello_link_iface(nbr, &nbr_count);

	if (!iface)
		return -1;

	if (!iface->operative)
		return 0;

	debug_evt_ldp_sync("%s: interface=%s, ifindex=%d, state=%d=%s, nbr_count=%d",
		__FUNCTION__, iface->name, iface->ifindex,
		iface->ldp_sync.state, ldp_sync_state_name(iface->ldp_sync.state), nbr_count);

	if ((event == LDP_SYNC_EVT_SESSION_CLOSE || event == LDP_SYNC_EVT_ADJ_DEL) &&
	    (nbr_count > 1))
	{
		// Process these events when last neighbor leaves interface.
		return 0;
	}

	return ldp_sync_fsm(iface, event);
}

int
ldp_sync_fsm_helper_state_req(struct ldp_igp_sync_if_state_req *state_req)
{
	debug_evt_ldp_sync("%s: interface %s (%d) ",
		    __func__, state_req->name, state_req->ifindex);

	struct iface *iface = if_lookup_name(leconf, state_req->name);
// TODO: From Mark: the library 'if' module should have all the right kinds of access - take a look at lib/if.h ? it looks like there's access by ifindex (and vrf).

	if (!iface)
	{
		debug_evt_ldp_sync("%s: Warning: failed to lookup interface %s (%d) ", __func__, state_req->name, state_req->ifindex);
		return send_ldp_sync_state_update_msg(state_req->name, state_req->ifindex, false);
	}

	return send_ldp_sync_state_update_msg(state_req->name, state_req->ifindex,
		(iface->ldp_sync.state != LDP_SYNC_STA_REQ_ACH));
}

static int
ldp_sync_fsm_init(struct iface *iface, int state)
{
	debug_evt_ldp_sync("%s: interface %s",
		    __func__, iface->name);

	bool verbose = false;

	int old_state = iface->ldp_sync.state;

	iface->ldp_sync.state = state;
	stop_wait_for_ldp_sync_timer(iface);

	send_ldp_sync_state_update_msg(iface->name, iface->ifindex,
		(iface->ldp_sync.state != LDP_SYNC_STA_REQ_ACH));

	if (verbose || old_state != iface->ldp_sync.state)
	{
		debug_evt_ldp_sync("%s: resulted in "
		    "changing state for interface %s from %s (%d) to %s (%d)",
		    __func__,
		    iface->name, ldp_sync_state_name(old_state), old_state,
		    ldp_sync_state_name(iface->ldp_sync.state),
		    iface->ldp_sync.state);
	}

	return 0;
}

int
ldp_sync_fsm(struct iface *iface, enum ldp_sync_event event)
{
	bool 		verbose = false; // LDP_SYNC_TODO remove me
	int		old_state = iface->ldp_sync.state;
	int		new_state = 0;
	int		i;

	for (i = 0; ldp_sync_fsm_tbl[i].state != -1; i++)
		if ((ldp_sync_fsm_tbl[i].state & old_state) &&
		    (ldp_sync_fsm_tbl[i].event == event)) {
			new_state = ldp_sync_fsm_tbl[i].new_state;
			break;
		}

	if (ldp_sync_fsm_tbl[i].state == -1) {
		/* event outside of the defined fsm, ignore it. */
		log_warnx("%s: interface %s, event %s (%d) not expected in "
		    "state %s (%d) ", __func__, iface->name,
		    ldp_sync_event_names[event], event,
		    ldp_sync_state_name(old_state), old_state);
		return (0);
	}

	if (new_state != 0)
		iface->ldp_sync.state = new_state;

	switch (ldp_sync_fsm_tbl[i].action) {
	case LDP_SYNC_ACT_IFACE_START_SYNC:
		ldp_sync_act_iface_start_sync(iface);
		break;
	case LDP_SYNC_ACT_LDP_START_SYNC:
		ldp_sync_act_ldp_start_sync(iface);
		break;
	case LDP_SYNC_ACT_LDP_COMPLETE_SYNC:
		ldp_sync_act_ldp_complete_sync(iface);
		break;
	case LDP_SYNC_ACT_CONFIG_LDP_OFF:
		ldp_sync_fsm_init(iface, LDP_SYNC_STA_REQ_NOT_ACH);
		break;
	case LDP_SYNC_ACT_IFACE_SHUTDOWN:
		ldp_sync_fsm_init(iface, iface->ldp_sync.state);
		break;
	case LDP_SYNC_ACT_IFACE_ANNOUNCE: // TODO REMOVE ME?
	case LDP_SYNC_ACT_NOTHING:
		/* do nothing */
		break;
	}

	if (old_state != iface->ldp_sync.state) {

		debug_evt_ldp_sync("%s: event %s (%d) resulted in action %s (%d) and "
		    "changing state for interface %s from %s (%d) to %s (%d)",
		    __func__, ldp_sync_event_names[event],
		    event,
		    ldp_sync_action_names[ldp_sync_fsm_tbl[i].action],
		    ldp_sync_fsm_tbl[i].action,
		    iface->name, ldp_sync_state_name(old_state), old_state,
		    ldp_sync_state_name(iface->ldp_sync.state),
		    iface->ldp_sync.state);

	}
	else if (verbose)
	{
		debug_evt_ldp_sync("%s: event %s (%d) resulted in action %s (%d) "
		    "for interface %s, remaining in state %s (%d)",
		    __func__, ldp_sync_event_names[event],
		    event,
		    ldp_sync_action_names[ldp_sync_fsm_tbl[i].action],
		    ldp_sync_fsm_tbl[i].action,
		    iface->name,
		    ldp_sync_state_name(iface->ldp_sync.state),
		    iface->ldp_sync.state);
	}

	return (0);
}

void
ldp_sync_fsm_reset_all(void)
{
	struct iface		*iface;

	RB_FOREACH(iface, iface_head, &leconf->iface_tree)
		ldp_sync_fsm(iface, LDP_SYNC_EVT_CONFIG_LDP_OFF);
}

