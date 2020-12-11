from topolog import logger

class SnmpTester(object):
    "A helper class for testing SNMP"

    def __init__(self, router, iface, community, version):
        self.community = community
        self.version = version
        self.router = router
        self.iface = iface
        logger.info("created SNMP tester: SNMPv{0} community:{1}".format(
            self.version, self.community)
        )

    def _snmp_config(self):
        """
        Helper function to build a string with SNMP
        configuration for commands.
        """
        return "-v {0} -c {1} {2}".format(self.version, self.community, self.iface)
    
    @staticmethod
    def _get_snmp_value(snmp_output):
        tokens = snmp_output.strip().split()

        if len(tokens) != 4:
            return None

        # third toekn is the value of the object
        return tokens[3]

    def _parse_multiline(self, snmp_output):
        results = snmp_output.strip().split('\r\n')
        
        values = []
        for response in results:
            values.append(self._get_snmp_value(response))

        return values

    def get(self, oid):
        cmd = "snmpget {0} {1}".format(self._snmp_config(), oid)

        result = self.router.cmd(cmd)
        return self._get_snmp_value(result)

    def get_next(self, oid):
        cmd = "snmpgetnext {0} {1}".format(self._snmp_config(), oid)

        result = self.router.cmd(cmd)
        return self._get_snmp_value(result)
        

    def walk(self, oid):
        cmd = "snmpwalk {0} {1}".format(self._snmp_config(), oid)

        result = self.router.cmd(cmd)
        return self._parse_multiline(result)

    def test_oid(self, oid, value):
        return self.get_next(oid) == value

    def test_oid_walk(self, oid, values):
        return self.walk(oid) == values
