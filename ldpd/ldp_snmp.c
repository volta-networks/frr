/*
 * LDP SNMP support
 * Copyright (C) 2020 Volta Networks, Inc.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * This is minimal read-only implementations providing
 * mplsLdpModuleReadOnlyCompliance
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "vrf.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "memory.h"
#include "smux.h"
#include "libfrr.h"
#include "version.h"
#include "ldpd.h"

/* MPLS-LDP-STD-MIB. */
#define MPLS_LDP_STD_MIB 1, 3, 6, 1, 2, 1, 10, 166, 4

#define MPLS_LDP_LSR_LOOP_DETECTION_CAPABLE 0

/* SNMP value hack. */
#define COUNTER32 ASN_COUNTER
#define INTEGER ASN_INTEGER
#define UNSIGNED32 ASN_GAUGE
#define TIMESTAMP ASN_TIMETICKS
#define TIMETICKS ASN_TIMETICKS
#define STRING ASN_OCTET_STR

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

/* ISIS-MIB instances. */
static oid ldp_oid[] = {MPLS_LDP_STD_MIB};

/* Hook functions. */

static uint8_t *ldpLoopDetectCap(struct variable *v, oid name[], size_t *length,
                           int exact, size_t *var_len,
                           WriteMethod **write_method)
{
        if (smux_header_generic(v, name, length, exact, var_len, write_method)
            == MATCH_FAILED)
                return NULL;

syslog(LOG_INFO, "SNMPDBG: %s: %d: getpid=%d: ldpd_process=%d", __FUNCTION__, __LINE__, getpid(), ldpd_process);

	// SNMP_TODO: return correct value...
        return SNMP_INTEGER(1);
}

static struct variable ldp_variables[] = {
	{MPLS_LDP_LSR_LOOP_DETECTION_CAPABLE, INTEGER, RONLY, ldpLoopDetectCap, 3, {1, 1, 2}},
};

/* Register MPLS-LDP-STD-MIB. */
static int ldp_snmp_init(struct thread_master *tm)
{
syslog(LOG_INFO, "SNMPDBG: %s: %d: getpid=%d: ldpd_process=%d", __FUNCTION__, __LINE__, getpid(), ldpd_process);

	if (ldpd_process != PROC_LDP_ENGINE)
	{
		return 0;
	}

	/* Perform MIB registration for the PROC_LDP_ENGINE */
syslog(LOG_INFO, "SNMPDBG: %s: %d: getpid=%d: ldpd_process=%d", __FUNCTION__, __LINE__, getpid(), ldpd_process);

	smux_init(tm);

	smux_agentx_enable_cmd();

	REGISTER_MIB("mibII/ldp", ldp_variables, variable, ldp_oid);

	return 0;
}

static int ldp_snmp_module_init(void)
{
	hook_register(frr_late_init, ldp_snmp_init);

	return 0;
}

FRR_MODULE_SETUP(.name = "ldp_snmp", .version = FRR_VERSION,
		 .description = "ldp AgentX SNMP module",
		 .init = ldp_snmp_module_init, )
