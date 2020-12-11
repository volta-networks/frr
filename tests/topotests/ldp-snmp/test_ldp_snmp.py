#!/usr/bin/env python

#
# test_ldp_isis_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_ldp_vpls_topo1.py:

                   +---------+                +---------+
                   |         |                |         |
                   |   CE1   |                |   CE2   |
                   |         |                |         |
                   +---------+                +---------+
ce1-eth0 (172.16.1.1/24)|                          |ce2-eth0 (172.16.1.2/24)
                        |                          |
                        |                          |
                rt1-eth0|                          |rt2-eth0
                   +---------+  10.0.1.0/24   +---------+
                   |         |rt1-eth1        |         |
                   |   RT1   +----------------+   RT2   |
                   | 1.1.1.1 |        rt2-eth1| 2.2.2.2 |
                   |         |                |         |
                   +---------+                +---------+
                rt1-eth2|                          |rt2-eth2
                        |                          |
                        |                          |
             10.0.2.0/24|        +---------+       |10.0.3.0/24
                        |        |         |       |
                        |        |   RT3   |       |
                        +--------+ 3.3.3.3 +-------+
                         rt3-eth2|         |rt3-eth1
                                 +---------+
                                      |rt3-eth0
                                      |
                                      |
              ce3-eth0 (172.16.1.3/24)|
                                 +---------+
                                 |         |
                                 |   CE3   |
                                 |         |
                                 +---------+
"""

import os
import re
import sys
import pytest
import json
from time import sleep
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.snmptest import SnmpTester

# Required to instantiate the topology builder class.
from mininet.topo import Topo


class TemplateTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        #
        # Define FRR Routers
        #
        for router in ["ce1", "ce2", "ce3", "r1", "r2", "r3"]:
            tgen.add_router(router)

        #
        # Define connections
        #
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["ce1"])
        switch.add_link(tgen.gears["r1"])

        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["ce2"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["ce3"])
        switch.add_link(tgen.gears["r3"])

        switch = tgen.add_switch("s4")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s5")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r3"])

        switch = tgen.add_switch("s6")
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        # Don't start the following in the CE nodes
        if router.name[0] == "r":
            router.load_config(
                TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
            )
            router.load_config(
                TopoRouter.RD_LDP, os.path.join(CWD, "{}/ldpd.conf".format(rname)),
                "-M /usr/lib/frr/modules/ldpd_snmp.so"
            )
            router.load_config(
                TopoRouter.RD_SNMP, os.path.join(CWD, "{}/snmpd.conf".format(rname)),
                "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX,trap"
            )

    tgen.start_router()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

def router_compare_json_output(rname, command, reference):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 80 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=160, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg

def test_isis_convergence():
    logger.info("Test: check ISIS adjacencies")
    tgen = get_topogen()

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "show_yang_interface_isis_adjacencies.ref")

def test_ldp_adjacencies():
    logger.info("Test: verify LDP adjacencies")
    tgen = get_topogen()

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp discovery json", "show_ldp_discovery.ref"
        )

def test_ldp_neighbors():
    logger.info("Test: verify LDP neighbors")
    tgen = get_topogen()

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp neighbor json", "show_ldp_neighbor.ref"
        )

def test_r1_converge_snmp():
    "Wait for protocol convergence"
    tgen = get_topogen()

    #tgen.mininet_cli()
    r1 = tgen.net.get("r1")
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid('mplsLdpLsrLoopDetectionCapable', "none(1)")
    assert r1_snmp.test_oid_walk('mplsLdpPeerLdpId', ['2.2.2.2:0', '3.3.3.3:0'])
    assert r1_snmp.test_oid_walk('mplsLdpPeerTransportAddrType', ['ipv4(1)', 'ipv4(1)'])

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

