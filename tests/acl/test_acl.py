import os
import time
import random
import logging
import pprint
import pytest

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from abc import ABCMeta, abstractmethod

from tests.acl.acl_test_constants import (
    DUT_TMP_DIR,
    FILES_DIR,
    TEMPLATE_DIR,
    ACL_RULES_FULL_TEMPLATE,
    ACL_RULES_PART_TEMPLATES,
    ACL_REMOVE_RULES_FILE,
    LOG_EXPECT_ACL_RULE_CREATE_RE,
    LOG_EXPECT_ACL_RULE_REMOVE_RE,
    DEFAULT_SRC_IP,
    DOWNSTREAM_DST_IP,
    DOWNSTREAM_IP_TO_ALLOW,
    DOWNSTREAM_IP_TO_BLOCK,
    UPSTREAM_DST_IP,
    UPSTREAM_IP_TO_ALLOW,
    UPSTREAM_IP_TO_BLOCK
)

from tests.common import reboot, port_toggle
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.acl,
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("any")
]


class BaseAclTest(object):
    """Base class for testing ACL rules.

    Subclasses must provide `setup_rules` method to prepare ACL rules for traffic testing.

    They can optionally override `teardown_rules`, which will otherwise remove the rules by
    applying an empty configuration file.
    """

    __metaclass__ = ABCMeta

    ACL_COUNTERS_UPDATE_INTERVAL_SECS = 10

    @abstractmethod
    def setup_rules(self, dut, acl_table):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        pass

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo):
        """Perform actions after rules have been applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_arp_entries: A function to populate ARP/FDB tables for VLAN interfaces.
            tbinfo: Information about the testbed.

        """
        pass

    def teardown_rules(self, dut):
        """Tear down ACL rules once the tests have completed.

        Args:
            dut: The DUT having ACLs applied.

        """
        logger.info("Finished with tests, removing all ACL rules...")

        # Copy empty rules configuration
        dut.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=DUT_TMP_DIR)
        remove_rules_dut_path = os.path.join(DUT_TMP_DIR, ACL_REMOVE_RULES_FILE)

        # Remove the rules
        logger.info("Applying \"{}\"".format(remove_rules_dut_path))
        dut.command("config acl update full {}".format(remove_rules_dut_path))

    @pytest.fixture(scope="class", autouse=True)
    def acl_rules(self, duthosts, rand_one_dut_hostname, localhost, setup, acl_table, populate_vlan_arp_entries, tbinfo):
        """Setup/teardown ACL rules for the current set of tests.

        Args:
            duthosts: All DUTs belong to the testbed.
            rand_one_dut_hostname: hostname of a random chosen dut to run test.
            localhost: The host from which tests are run.
            setup: Parameters for the ACL tests.
            acl_table: Configuration info for the ACL table.
            populate_vlan_arp_entries: A function to populate ARP/FDB tables for VLAN interfaces.
            tbinfo: Information about the testbed.

        """
        duthost = duthosts[rand_one_dut_hostname]
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="acl_rules")
        loganalyzer.load_common_config()

        try:
            loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
            with loganalyzer:
                self.setup_rules(duthost, acl_table)

            self.post_setup_hook(duthost, localhost, populate_vlan_arp_entries, tbinfo)
        except LogAnalyzerError as err:
            # Cleanup Config DB if rule creation failed
            logger.error("ACL table creation failed, attempting to clean-up...")
            self.teardown_rules(duthost)
            raise err

        try:
            yield
        finally:
            loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_REMOVE_RE]
            with loganalyzer:
                logger.info("Removing ACL rules")
                self.teardown_rules(duthost)

    @pytest.yield_fixture(scope="class", autouse=True)
    def counters_sanity_check(self, duthosts, rand_one_dut_hostname, acl_rules, acl_table):
        """Validate that the counters for each rule in the rules list increased as expected.

        This fixture yields a list of rule IDs. The test case should add on to this list if
        it is required to check the rule for increased counters.

        After the test cases pass, the fixture will wait for the ACL counters to update and then
        check if the counters for each rule in the list were increased.

        Args:
            duthosts: All DUTs belong to the testbed.
            rand_one_dut_hostname: hostname of a random chosen dut to run test.
            acl_rules: Fixture that sets up the ACL rules.
            acl_table: Fixture that sets up the ACL table.

        """
        duthost = duthosts[rand_one_dut_hostname]
        table_name = acl_table["table_name"]
        acl_facts_before_traffic = duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"][table_name]["rules"]

        rule_list = []
        yield rule_list

        if not rule_list:
            return

        # Wait for orchagent to update the ACL counters
        time.sleep(self.ACL_COUNTERS_UPDATE_INTERVAL_SECS)

        acl_facts_after_traffic = duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"][table_name]["rules"]

        assert len(acl_facts_after_traffic) == len(acl_facts_before_traffic)

        for rule in rule_list:
            rule = "RULE_{}".format(rule)

            counters_before = acl_facts_before_traffic[rule]
            logger.info("Counters for ACL rule \"{}\" before traffic:\n{}"
                        .format(rule, pprint.pformat(counters_before)))

            counters_after = acl_facts_after_traffic[rule]
            logger.info("Counters for ACL rule \"{}\" after traffic:\n{}"
                        .format(rule, pprint.pformat(counters_after)))

            assert counters_after["packets_count"] > counters_before["packets_count"]
            assert counters_after["bytes_count"] > counters_before["bytes_count"]

    @pytest.fixture(params=["downlink->uplink", "uplink->downlink"])
    def direction(self, request):
        """Parametrize test based on direction of traffic."""
        return request.param

    def get_src_port(self, setup, direction):
        """Get a source port for the current test."""
        src_ports = setup["downstream_port_ids"] if direction == "downlink->uplink" else setup["upstream_port_ids"]
        return random.choice(src_ports)

    def get_dst_ports(self, setup, direction):
        """Get the set of possible destination ports for the current test."""
        return setup["upstream_port_ids"] if direction == "downlink->uplink" else setup["downstream_port_ids"]

    def get_dst_ip(self, direction):
        """Get the default destination IP for the current test."""
        return UPSTREAM_DST_IP if direction == "downlink->uplink" else DOWNSTREAM_DST_IP

    def tcp_packet(self, setup, direction, ptfadapter):
        """Generate a TCP packet for testing."""
        return testutils.simple_tcp_packet(
            eth_dst=setup["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_dst=self.get_dst_ip(direction),
            ip_src=DEFAULT_SRC_IP,
            tcp_sport=0x4321,
            tcp_dport=0x51,
            ip_ttl=64
        )

    def udp_packet(self, setup, direction, ptfadapter):
        """Generate a UDP packet for testing."""
        return testutils.simple_udp_packet(
            eth_dst=setup["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_dst=self.get_dst_ip(direction),
            ip_src=DEFAULT_SRC_IP,
            udp_sport=1234,
            udp_dport=80,
            ip_ttl=64
        )

    def icmp_packet(self, setup, direction, ptfadapter):
        """Generate an ICMP packet for testing."""
        return testutils.simple_icmp_packet(
            eth_dst=setup["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_dst=self.get_dst_ip(direction),
            ip_src=DEFAULT_SRC_IP,
            icmp_type=8,
            icmp_code=0,
            ip_ttl=64,
        )

    def expected_mask_routed_packet(self, pkt):
        """Generate the expected mask for a routed packet."""
        exp_pkt = pkt.copy()
        exp_pkt["IP"].ttl -= 1
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
        exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
        return exp_pkt

    def test_unmatched_blocked(self, setup, direction, ptfadapter):
        """Verify that unmatched packets are dropped."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)

    def test_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward a packet on source IP."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].src = "20.0.0.2"

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(1)

    def test_rules_priority_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we respect rule priorites in the forwarding case."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].src = "20.0.0.7"

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(20)

    def test_rules_priority_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we respect rule priorites in the drop case."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].src = "20.0.0.3"

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(7)

    def test_dest_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward a packet on destination IP."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].dst = DOWNSTREAM_IP_TO_ALLOW if direction == "uplink->downlink" else UPSTREAM_IP_TO_ALLOW

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(2 if direction == "uplink->downlink" else 3)

    def test_dest_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop a packet on destination IP."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].dst = DOWNSTREAM_IP_TO_BLOCK if direction == "uplink->downlink" else UPSTREAM_IP_TO_BLOCK

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(15 if direction == "uplink->downlink" else 16)

    def test_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop a packet on source IP."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].src = "20.0.0.6"

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(14)

    def test_udp_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward a UDP packet on source IP."""
        pkt = self.udp_packet(setup, direction, ptfadapter)
        pkt["IP"].src = "20.0.0.4"

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(13)

    def test_udp_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop a UDP packet on source IP."""
        pkt = self.udp_packet(setup, direction, ptfadapter)
        pkt["IP"].src = "20.0.0.8"

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(26)

    def test_icmp_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop an ICMP packet on source IP."""
        pkt = self.icmp_packet(setup, direction, ptfadapter)
        pkt["IP"].src = "20.0.0.8"

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(25)

    def test_icmp_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward an ICMP packet on source IP."""
        pkt = self.icmp_packet(setup, direction, ptfadapter)
        pkt["IP"].src = "20.0.0.4"

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(12)

    def test_l4_dport_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on L4 destination port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].dport = 0x1217

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(5)

    def test_l4_sport_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on L4 source port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].sport = 0x120D

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(4)

    def test_l4_dport_range_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on a range of L4 destination ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].dport = 0x123B

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(11)

    def test_l4_sport_range_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on a range of L4 source ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].sport = 0x123A

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(10)

    def test_l4_dport_range_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on a range of L4 destination ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].dport = 0x127B

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(22)

    def test_l4_sport_range_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on a range of L4 source ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].sport = 0x1271

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(17)

    def test_ip_proto_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on the IP protocol."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].proto = 0x7E

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(5)

    def test_tcp_flags_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on the TCP flags."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].flags = 0x1B

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(6)

    def test_l4_dport_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on L4 destination port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].dport = 0x127B

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(22)

    def test_l4_sport_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on L4 source port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].sport = 0x1271

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(10)

    def test_ip_proto_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on the IP protocol."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].proto = 0x7F

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(18)

    def test_tcp_flags_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on the TCP flags."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].flags = 0x24

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(5)

    def _verify_acl_traffic(self, setup, direction, ptfadapter, pkt, dropped):
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)

        if dropped:
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))
        else:
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))


class TestBasicAcl(BaseAclTest):
    """Test Basic functionality of ACL rules (i.e. setup with full update on a running device)."""

    def setup_rules(self, dut, acl_table):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        table_name = acl_table["table_name"]
        dut_conf_file_path = os.path.join(DUT_TMP_DIR, "acl_rules_{}.json".format(table_name))

        logger.info("Generating basic ACL rules config for ACL table \"{}\"".format(table_name))
        dut.template(src=os.path.join(TEMPLATE_DIR, ACL_RULES_FULL_TEMPLATE),
                     dest=dut_conf_file_path)

        logger.info("Applying ACL rules config \"{}\"".format(dut_conf_file_path))
        dut.command("config acl update full {}".format(dut_conf_file_path))


class TestIncrementalAcl(BaseAclTest):
    """Test ACL rule functionality with an incremental configuration.

    Verify that everything still works as expected when an ACL configuration is applied in
    multiple parts.
    """

    def setup_rules(self, dut, acl_table):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        table_name = acl_table["table_name"]

        logger.info("Generating incremental ACL rules config for ACL table \"{}\""
                    .format(table_name))

        for part, config_file in enumerate(ACL_RULES_PART_TEMPLATES):
            dut_conf_file_path = os.path.join(DUT_TMP_DIR, "acl_rules_{}_part_{}.json".format(table_name, part))
            dut.template(src=os.path.join(TEMPLATE_DIR, config_file), dest=dut_conf_file_path)

            logger.info("Applying ACL rules config \"{}\"".format(dut_conf_file_path))
            dut.command("config acl update incremental {}".format(dut_conf_file_path))


@pytest.mark.reboot
class TestAclWithReboot(TestBasicAcl):
    """Test ACL rule functionality with a reboot.

    Verify that configuration persists correctly after reboot and is applied properly
    upon startup.
    """

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo):
        """Save configuration and reboot after rules are applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_arp_entries: A fixture to populate ARP/FDB tables for VLAN interfaces.

        """
        dut.command("config save -y")
        reboot(dut, localhost)
        populate_vlan_arp_entries()


@pytest.mark.port_toggle
class TestAclWithPortToggle(TestBasicAcl):
    """Test ACL rule functionality after toggling ports.

    Verify that ACLs still function as expected after links flap.
    """

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo):
        """Toggle ports after rules are applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_arp_entries: A fixture to populate ARP/FDB tables for VLAN interfaces.

        """
        port_toggle(dut, tbinfo)
        populate_vlan_arp_entries()
