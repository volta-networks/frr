#!/usr/bin/env python

#
# test_bgp_dnmp_mplsl3vpn.py
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
test_bgp_snmp_mplsl3vpn.py: Test mplsL3Vpn MIB [RFC4382].
"""

import os
import sys
import json
from functools import partial
from time import sleep
import pytest

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

        # This function only purpose is to define allocation and relationship
        # between routers, switches and hosts.
        #
        #
        # Create routers
        tgen.add_router("r1")
        tgen.add_router("r2")
        tgen.add_router("r3")
        tgen.add_router("r4")
        tgen.add_router("ce1")
        tgen.add_router("ce2")

        # r1-r2
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        # r1-r3
        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r3"])

        # r1-r4
        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r4"])

        # r1-ce1
        switch = tgen.add_switch("s4")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["ce1"])

        # r2-r3
        switch = tgen.add_switch("s5")
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears["r3"])

        # r3-r4
        switch = tgen.add_switch("s6")
        switch.add_link(tgen.gears["r3"])
        switch.add_link(tgen.gears["r4"])

        # r4-ce2
        switch = tgen.add_switch("s7")
        switch.add_link(tgen.gears["r4"])
        switch.add_link(tgen.gears["ce2"])



def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(TemplateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    # setup vrf-a in r1 
    r1.run("ip link add vrf-a type vrf table 1001")
    r1.run("ip link set up dev vrf-a")
    r4.run("ip link add vrf-a type vrf table 1001")
    r4.run("ip link set up dev vrf-a")

    #enslave vrf interfaces
    r1.run("ip link set r1-eth3 master vrf-a")
    r4.run("ip link set r4-eth1 master vrf-a")

    r1.run("sysctl -w net.ipv4.ip_forward=1")
    r2.run("sysctl -w net.ipv4.ip_forward=1")
    r3.run("sysctl -w net.ipv4.ip_forward=1")
    r4.run("sysctl -w net.ipv4.ip_forward=1")
    r1.run("sysctl -w net.mpls.conf.r1-eth0.input=1")
    r1.run("sysctl -w net.mpls.conf.r1-eth1.input=1")
    r1.run("sysctl -w net.mpls.conf.r1-eth2.input=1")
    r2.run("sysctl -w net.mpls.conf.r1-eth0.input=1")
    r2.run("sysctl -w net.mpls.conf.r1-eth1.input=1")
    r3.run("sysctl -w net.mpls.conf.r1-eth0.input=1")
    r3.run("sysctl -w net.mpls.conf.r1-eth1.input=1")
    r3.run("sysctl -w net.mpls.conf.r1-eth2.input=1")
    r4.run("sysctl -w net.mpls.conf.r1-eth0.input=1")
    r4.run("sysctl -w net.mpls.conf.r1-eth1.input=1")



    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            "-M /usr/lib/frr/modules/bgpd_snmp.so"
        )
        router.load_config(
            TopoRouter.RD_SNMP, os.path.join(CWD, "{}/snmpd.conf".format(rname)),
            "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX,trap"
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_r1_converge_snmp():
    "Wait for protocol convergence"
    tgen = get_topogen()

    #tgen.mininet_cli()
    r1 = tgen.net.get("r1")
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")
    assert r1_snmp.test_oid('bgpVersin', None)
    assert r1_snmp.test_oid("bgpVersion", '10')
    assert r1_snmp.test_oid_walk('bgpPeerLocalAddr', ['0.0.0.0', '0.0.0.0'])

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
