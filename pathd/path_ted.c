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
 */

#include "stdlib.h"

// link state includes
//#include "if.h"
//#include "linklist.h"
//#include "command.h"
//#include "memory.h"
//#include "table.h"
//#include "link_state.h"
// link state includes

#include "log.h"

#include "pathd/path_errors.h"
#include "pathd/path_ted.h"

#ifndef VTYSH_EXTRACT_PL
#include "pathd/path_ted_clippy.c"
#endif

static struct ls_ted *path_ted_create_ted(void);
static bool path_ted_is_initialized(void);
static void path_ted_register_vty(void);
static void path_ted_unregister_vty(void);
static int path_ted_config_write(struct vty *vty);
static int path_ted_start_importing_igp(char* daemon_str);
static int path_ted_stop_importing_igp(void);
static enum zclient_send_status path_ted_link_state_sync(void);
static int path_ted_timer_handler(struct thread *thread);

extern struct zclient *zclient;
struct path_ted_req {
	// Remote client session tuple
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;
};

#define TIMER_RETRY_DELAY 5 //Timeout in seconds between ls sync request
enum igp_import {IMPORT_UNKNOWN = 0, IMPORT_ISIS, IMPORT_OSPFv2, IMPORT_OSPFv3};
struct ted_state {
	struct thread_master *main;
	/* Status of TED: enable or disable */
	bool enabled;
	/* From which igp is going to receive data */
	enum igp_import import;
	/* The TED itself as in link_state.h */
	struct ls_ted *ted;
	/* Timer for ted sync */
	struct thread *t_link_state_sync;
	/* delay interval in seconds */
	unsigned int link_state_delay_interval;
};
static struct ted_state ted_state_g = {0};

static const uint32_t TED_KEY = 1;
static const uint32_t TED_ASN = 1;
static const char *TED_NAME = "PATHD TED";

/*
 * path_path_ted public API function implementations
 */

void path_ted_init(struct thread_master *master)
{
	ted_state_g.main = master;
	ted_state_g.link_state_delay_interval = TIMER_RETRY_DELAY;
	path_ted_register_vty();

}

int path_ted_teardown()
{
	path_ted_unregister_vty();
	path_ted_stop_importing_igp();
	ls_ted_del_all(ted_state_g.ted);
	return 0;
}

/**
 * Set all needed to receive igp data.
 *
 * @return		true if ok
 *
 */
int path_ted_start_importing_igp(char* daemon_str)
{
	int status=0;
	if (ls_register(zclient, false/*client*/) != 0) {
		zlog_err("%s: PATHD-TED: Unable to register Link State\n", __func__);
		status = 1;
	}else
		if(path_ted_link_state_sync() != -1){
			if ( strcmp(daemon_str, "ospfv2")==0)
				ted_state_g.import = IMPORT_OSPFv2;
			else if ( strcmp(daemon_str, "ospfv3")==0)
				ted_state_g.import = IMPORT_OSPFv3;
			else if ( strcmp(daemon_str, "isis")==0)
				ted_state_g.import = IMPORT_ISIS;
			zlog_debug( "%s: PATHD-TED: Importing %s data ON", __func__,
				    ted_state_g.import==IMPORT_OSPFv2?"ospfv2":ted_state_g.import==IMPORT_OSPFv3?"ospfv3":ted_state_g.import==IMPORT_ISIS?"isis":"none");
		}else{
			status = 1;
		}
	return status;
}

/**
 * Unset all needed to receive igp data.
 *
 * @return		true if ok
 *
 */
int path_ted_stop_importing_igp(void)
{
	int status=0;
	if (ls_unregister(zclient, false/*client*/) != 0) {
		zlog_err("%s: PATHD-TED: Unable to unregister Link State\n", __func__);
		status = 1;
	}else{
		ted_state_g.import= IMPORT_UNKNOWN;
		zlog_debug( "%s: PATHD-TED: Importing igp data OFF", __func__);
		path_ted_timer_cancel();
	}
	return status;
}
/**
 * Check for ted status
 *
 * @return		true if ok
 *
 */
bool path_ted_is_initialized()
{
	if (ted_state_g.ted == NULL) {
		zlog_debug("PATHD TED ls_ted not initialized");
		return false;
	}

	return true;
}

/*
 * Internal util functions
 */

/**
 * Creates an empty ted
 *
 * @param void
 *
 * @return		Ptr to ted or NULL
 */
struct ls_ted *path_ted_create_ted()
{
	struct ls_ted *ted = ls_ted_new(TED_KEY, TED_NAME, TED_ASN);
	if (ted == NULL) {
		zlog_warn(
			  "Unable to initialize TED Key [%d] ASN [%d] Name [%s]",
			  TED_KEY, TED_ASN, TED_NAME);
	}else{
		zlog_info(
			  "Initialize TED Key [%d] ASN [%d] Name [%s]",
			  TED_KEY, TED_ASN, TED_NAME);
	}

	return ted;
}

struct ls_node *path_ted_query_router_by_ipv4(struct in_addr router_id)
{
	if (!path_ted_is_initialized()) {
		return NULL;
	}

	return ls_find_vertex_by_key(ted_state_g.ted,
				     ((uint64_t)router_id.s_addr)
				     & 0xffffffff)->node;
}

struct ls_node *path_ted_query_router_by_ipv6(struct in6_addr router6_id)
{
	if (!path_ted_is_initialized()) {
		return NULL;
	}
	/* For IPv6, the key is the lower 64 bits of the IP */
	return ls_find_vertex_by_key(
				     ted_state_g.ted,
				     (uint64_t)(router6_id.s6_addr32[0] & 0xffffffff)
				     | ((uint64_t)router6_id.s6_addr32[1] << 32))->node;
}

int path_ted_rcvd_message(struct ls_message *msg, uint64_t key)
{
	if (!path_ted_is_initialized()) {
		return MPLS_LABEL_NONE;
	}

	struct ls_node *new_node;
	struct ls_attributes *new_attr;
	char buf1[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];
	assert(msg != NULL);

	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		zlog_debug("TED received Node message");
		new_node = ls_node_new( msg->data.node->adv, msg->data.node->router_id,
					msg->data.node->router6_id);
		// More node data
		new_node->adv = msg->data.node->adv;
		// More node data
		ls_vertex_add(ted_state_g.ted, new_node);
		break;

	case LS_MSG_TYPE_ATTRIBUTES:
		zlog_debug("TED received Attributes message");
		new_attr = ls_attributes_new(msg->data.node->adv,
					     msg->data.attr->standard.local,
					     msg->data.attr->standard.local6,
					     msg->data.attr->standard.local_id);
		// More attr data
		SET_FLAG(new_attr->flags, LS_ATTR_NEIGH_ADDR);
		new_attr->standard.remote = msg->data.attr->standard.remote;
		SET_FLAG(new_attr->flags, LS_ATTR_NEIGH_ADDR6);
		new_attr->standard.remote6 = msg->data.attr->standard.remote6;
		SET_FLAG(new_attr->flags, LS_ATTR_ADJ_SID);
		new_attr->adj_sid->sid = msg->data.attr->adj_sid->sid;
		new_attr->adv = msg->data.attr->adv;
		;
		// More attr data
		struct ls_edge *edge = ls_edge_add(ted_state_g.ted, new_attr);
		// TODO : search in nodes list of ted and link attribute
		struct ls_vertex *vertex =
			ls_find_vertex_by_key(ted_state_g.ted, key);
		if( vertex /* Todo proper match && vertex->node->adv == edge->attributes->adv*/){
			// it's a match
			frr_inet_ntop(AF_INET, &key, buf1, sizeof(buf1));
			frr_inet_ntop(AF_INET,
				      &msg->data.attr->adv.id.ip.addr.s_addr,
				      buf2, sizeof(buf2));
			zlog_debug(
				   "TED received Attributes message, (%s->(%s ¡connect attributes!",
				   buf1, buf2);
			ls_connect_vertices(vertex, NULL, edge);
		}
		break;

	case LS_MSG_TYPE_PREFIX:
		zlog_debug("TED received Prefix message");
		// rebuild ls_prefix
		struct ls_prefix *ls_pre;
		ls_pre = ls_prefix_new(msg->data.prefix->adv, msg->data.prefix->pref);
		// rebuild ls_subnet
		ls_subnet_add(ted_state_g.ted, ls_pre);
		break;

	default:
		zlog_debug("TED received unknown message type [%d]", msg->type);
		break;
	}
	ls_dump_ted(ted_state_g.ted);
	return 0;
}

uint32_t path_ted_query_type_f(struct ipaddr *local, struct ipaddr *remote)
{
	if (!path_ted_is_initialized()) {
		return MPLS_LABEL_NONE;
	}
	uint32_t sid = MPLS_LABEL_NONE;
	struct ls_edge *edge;
	switch(local->ipa_type){
	case IPADDR_V4:
		// We have local and remote ip
		// so check all attributes in ted
		frr_each(edges, &ted_state_g.ted->edges, edge) {
			if(edge->attributes->standard.local.s_addr==local->ip._v4_addr.s_addr
			   &&
			   edge->attributes->standard.remote.s_addr==remote->ip._v4_addr.s_addr)
			{
				sid = edge->attributes->adj_sid[0].sid; // from primary
				break;
			}
		}
		break;
	case IPADDR_V6:
		break;
	case IPADDR_NONE:
		break;
	}

	return sid;
}

uint32_t path_ted_query_type_c(struct prefix *prefix, uint8_t algo)
{
	if (!path_ted_is_initialized()) {
		return MPLS_LABEL_NONE;
	}
	uint32_t sid = MPLS_LABEL_NONE;
	struct ls_subnet *subnet;
	switch (prefix->family) {
	case AF_INET:
		frr_each (subnets, &ted_state_g.ted->subnets, subnet) {
			if ((subnet->ls_pref->pref.family == prefix->family)
			    && (memcmp(&subnet->ls_pref->pref.u.prefix4,
				       &prefix->u.prefix4, prefix_blen(prefix))
				== 0)
			    && (subnet->ls_pref->sr.algo == algo)) {
				sid = subnet->ls_pref->sr.sid;
				break;
			}
		}
		break;
	case AF_INET6:
		break;
	default:
		break;
	}

	return sid;
}

uint32_t path_ted_query_type_e(struct prefix *prefix, uint32_t iface_id)
{
	if (!path_ted_is_initialized()) {
		return MPLS_LABEL_NONE;
	}
	uint32_t sid = MPLS_LABEL_NONE;
	struct ls_subnet *subnet;
	struct listnode *lst_node;
	struct ls_edge *edge;
	switch (prefix->family) {
	case AF_INET:
		frr_each (subnets, &ted_state_g.ted->subnets, subnet) {
			if ((subnet->ls_pref->pref.family == prefix->family)
			    && (memcmp(&subnet->ls_pref->pref.u.prefix4,
				       &prefix->u.prefix4, prefix_blen(prefix))
				== 0)){

				// from the vertex linked in subnet
				// loop over outgoing edges
				for (ALL_LIST_ELEMENTS_RO(subnet->vertex->outgoing_edges , lst_node, edge))
				{
					// and look for ifaceid
					// so get sid of attribute
					if(edge->attributes->standard.local_id == iface_id){
						sid = subnet->ls_pref->sr.sid;
						break;
					}
				}


			}
		}
		break;
	case AF_INET6:
		break;
	default:
		break;
	}

	return sid;
}

/*------------------------------------------------------------------------*
 * Followings are vty command functions.
 *------------------------------------------------------------------------*/
DEFUN (path_ted_on,
       path_ted_on_cmd,
       "pathd-ted on",
       NO_STR
       "Enable the TE database functionality\n")
{

	if (ted_state_g.enabled){
		zlog_debug( "%s: PATHD-TED: ON -> ON. Importing from igp (%d)", 
			    __func__, ted_state_g.import);
		return CMD_SUCCESS;
	}

	ted_state_g.ted = path_ted_create_ted();
	ted_state_g.enabled = true;
	zlog_debug( "%s: PATHD-TED: OFF -> ON. Importing from igp (%d)", 
		    __func__, ted_state_g.import);

	return CMD_SUCCESS;
}

DEFUN (no_path_ted,
       no_path_ted_cmd,
       "no pathd-ted [on]",
       NO_STR
       NO_STR
       "Disable the TE Database functionality\n")
{
	if (ted_state_g.enabled){
		zlog_debug( "%s: PATHD-TED: OFF -> OFF", __func__);
		return CMD_SUCCESS;
	}

	/* Remove TED */
	ls_ted_del_all(ted_state_g.ted);
	ted_state_g.enabled = false;
	zlog_debug( "%s: PATHD-TED: ON -> OFF", __func__);
	ted_state_g.import = IMPORT_UNKNOWN;
	if (ls_unregister(zclient, false/*client*/) != 0) {
		vty_out(vty, "Unable to unregister Link State\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFPY(path_ted_import,
       path_ted_import_cmd,
       "pathd-ted import from [ospfv2|ospfv3|isis]$import_daemon",
       "Enable the TE database fill with remote igp data\n"
       "import\n"
       "from\n"
       "Origin ospfv2\n"
       "Origin ospfv3\n"
       "Origin isis\n")
{

	if (ted_state_g.enabled)
		if(path_ted_start_importing_igp(import_daemon))
		{
			vty_out(vty, "Unable to start importing\n");
			return CMD_WARNING;
		}
	return CMD_SUCCESS;
}

DEFUN (no_path_ted_import,
       no_path_ted_import_cmd,
       "no pathd-ted import",
       NO_STR
       NO_STR
       "Disable the TE Database fill with remote igp data\n")
{

	if (ted_state_g.import)
	{
		if(path_ted_stop_importing_igp()){
			vty_out(vty, "Unable to stop importing\n");
			return CMD_WARNING;
		}
		else{
			zlog_debug( "%s: PATHD-TED: Importing igp data already OFF", __func__);
		}
	}
	return CMD_SUCCESS;
}

/**
 * Help fn to show ted related configuration
 *
 * @param vty
 *
 * @return		Status
 */
static int path_ted_config_write(struct vty *vty)
{

	if (ted_state_g.enabled) {
		vty_out(vty, " pathd-ted on\n");
		switch (ted_state_g.import)
		{
		case IMPORT_ISIS:
			vty_out(vty, " pathd-ted import from isis\n");
			break;
		case IMPORT_OSPFv2:
			vty_out(vty, " pathd-ted import from ospfv2\n");
			break;
		case IMPORT_OSPFv3:
			vty_out(vty, " pathd-ted import from ospfv3\n");
			break;
		default :
			break;
		}
	}
	return 0;
}

/**
 * Register the fn's for CLI and hook for config show
 *
 * @param void
 *
 */
static void path_ted_register_vty(void)
{
	hook_register(nb_client_debug_config_write,
		      path_ted_config_write);
	install_element(SR_TRAFFIC_ENG_NODE, &path_ted_on_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &no_path_ted_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &path_ted_import_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &no_path_ted_import_cmd);

}

/**
 * UnRegister the fn's for CLI and hook for config show
 *
 * @param void
 *
 */
static void path_ted_unregister_vty(void)
{
	hook_unregister(nb_client_debug_config_write,
			path_ted_config_write);
	uninstall_element(SR_TRAFFIC_ENG_NODE, &path_ted_on_cmd);
	uninstall_element(SR_TRAFFIC_ENG_NODE, &no_path_ted_cmd);
	uninstall_element(SR_TRAFFIC_ENG_NODE, &path_ted_import_cmd);
	uninstall_element(SR_TRAFFIC_ENG_NODE, &no_path_ted_import_cmd);

}

/**
 * Ask igp for a complete TED so far
 *
 * @param void
 * @param key	The key associated to the current node id
 *
 * @return		zclient status
 */
enum zclient_send_status path_ted_link_state_sync(void)
{
	enum zclient_send_status status;
	struct path_ted_req request;

	request.proto = zclient->redist_default;
	request.instance = zclient->instance;
	request.session_id = zclient->session_id;
	if((status = zclient_send_opaque(zclient, LINK_STATE_SYNC,
					  (uint8_t *)&request, sizeof(request))) == -1)
	{
		zlog_err( "%s: PATHD-TED: Opaque error asking for TED sync ", 
			  __func__);
		return status;
	}else{
		zlog_err( "%s: PATHD-TED: Opaque asked for TED sync ", 
			  __func__);
	}
	// Create timer
	thread_add_timer(ted_state_g.main, path_ted_timer_handler, &ted_state_g,
			 ted_state_g.link_state_delay_interval, &ted_state_g.t_link_state_sync);

	return status;
}

/**
 * Timer cb for check link state sync
 *
 * @param void
 * @param key	The key associated to the current node id
 *
 * @return		zclient status
 */
int path_ted_timer_handler(struct thread *thread)
{
	/* data unpacking */
	struct pcep_ctrl_timer_data *data = THREAD_ARG(thread);
	assert(data != NULL);
	// Retry the sync
	path_ted_link_state_sync();
}
/**
 * Cancel timer
 *
 * @param void
 *
 * @return		void status
 */
void path_ted_timer_cancel()
{
	if (ted_state_g.t_link_state_sync != NULL) {
		thread_cancel(&ted_state_g.t_link_state_sync);
		ted_state_g.t_link_state_sync = NULL;
	}
}
