import logging
import os
import pytest

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.acl.acl_test_base import (
    TEMPLATE_DIR,
    BaseAclTest,
    BaseHostResponder,
    BasicAclConfiguration,
    IncrementalAclConfiguration,
    BasicAclConfigurationWithPortToggle,
    BasicAclConfigurationWithReboot
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.acl,
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("t1")
]

DEFAULT_SRC_IP = "60c0:a800::5"

# TODO: These routes don't match the VLAN interface from the T0 topology
# This needs to be addressed when we adapt the v6 tests for T0.
DOWNSTREAM_DST_IP = "20c0:a800::2"
DOWNSTREAM_IP_TO_ALLOW = "20c0:a800::4"
DOWNSTREAM_IP_TO_BLOCK = "20c0:a800::8"

UPSTREAM_DST_IP = "40c0:a800::2"
UPSTREAM_IP_TO_ALLOW = "40c0:a800::4"
UPSTREAM_IP_TO_BLOCK = "40c0:a800::8"

ACL_RULES_FULL_TEMPLATE = "acltb_v6_test_rules.j2"
ACL_RULES_PART_TEMPLATES = tuple("acltb_v6_test_rules_part_{}.j2".format(i) for i in xrange(1, 3))


class AclIPv6Test(BaseAclTest):
    @pytest.fixture(scope="class")
    def table_type(self):
        return "L3V6"

    def get_dst_ip(self, direction):
        """Get the default destination IP for the current test."""
        return UPSTREAM_DST_IP if direction == "downlink->uplink" else DOWNSTREAM_DST_IP

    def tcp_packet(self, setup, direction, ptfadapter):
        """Generate a TCP packet for testing."""
        return testutils.simple_tcpv6_packet(
            eth_dst=setup["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_dst=self.get_dst_ip(direction),
            ipv6_src=DEFAULT_SRC_IP,
            tcp_sport=0x4321,
            tcp_dport=0x51,
            ipv6_hlim=64
        )

    def udp_packet(self, setup, direction, ptfadapter):
        """Generate a UDP packet for testing."""
        return testutils.simple_udpv6_packet(
            eth_dst=setup["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_dst=self.get_dst_ip(direction),
            ipv6_src=DEFAULT_SRC_IP,
            udp_sport=1234,
            udp_dport=80,
            ipv6_hlim=64
        )

    def icmp_packet(self, setup, direction, ptfadapter):
        """Generate an ICMP packet for testing."""
        return testutils.simple_icmpv6_packet(
            eth_dst=setup["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_dst=self.get_dst_ip(direction),
            ipv6_src=DEFAULT_SRC_IP,
            icmp_type=8,
            icmp_code=0,
            ipv6_hlim=64,
        )

    def expected_mask_routed_packet(self, pkt):
        """Generate the expected mask for a routed packet."""
        exp_pkt = pkt.copy()
        exp_pkt["IPv6"].hlim -= 1
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
        return exp_pkt

    def test_unmatched_blocked(self, setup, direction, ptfadapter):
        """Verify that unmatched packets are dropped."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)

    def test_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward a packet on source IP."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].src = "60c0:a800::6"

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(1)

    def test_rules_priority_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we respect rule priorites in the forwarding case."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].src = "60c0:a800::7"

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(20)

    def test_rules_priority_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we respect rule priorites in the drop case."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].src = "60c0:a800::4"

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(7)

    def test_dest_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward a packet on destination IP."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].dst = DOWNSTREAM_IP_TO_ALLOW if direction == "uplink->downlink" else UPSTREAM_IP_TO_ALLOW

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(2 if direction == "uplink->downlink" else 3)

    def test_dest_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop a packet on destination IP."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IP"].dst = DOWNSTREAM_IP_TO_BLOCK if direction == "uplink->downlink" else UPSTREAM_IP_TO_BLOCK

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(15 if direction == "uplink->downlink" else 16)

    def test_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop a packet on source IP."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].src = "60c0:a800::3"

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(14)

    def test_udp_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward a UDP packet on source IP."""
        pkt = self.udp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].src = "60c0:a800::8"

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(13)

    def test_udp_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop a UDP packet on source IP."""
        pkt = self.udp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].src = "60c0:a800::2"

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(26)

    def test_icmp_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop an ICMP packet on source IP."""
        pkt = self.icmp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].src = "60c0:a800::2"

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(25)

    def test_icmp_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward an ICMP packet on source IP."""
        pkt = self.icmp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].src = "60c0:a800::8"

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(12)

    def test_l4_dport_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on L4 destination port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].dport = 0x1217

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(5)

    def test_l4_sport_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on L4 source port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].sport = 0x120D

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(4)

    def test_l4_dport_range_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on a range of L4 destination ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].dport = 0x123B

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(11)

    def test_l4_sport_range_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on a range of L4 source ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].sport = 0x123A

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(10)

    def test_l4_dport_range_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on a range of L4 destination ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].dport = 0x127B

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(22)

    def test_l4_sport_range_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on a range of L4 source ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].sport = 0x1271

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(17)

    def test_ip_proto_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on the IP protocol."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].nh = 0x7E

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(5)

    def test_tcp_flags_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and forward on the TCP flags."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].flags = 0x1B

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, False)
        counters_sanity_check.append(6)

    def test_l4_dport_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on L4 destination port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].dport = 0x127B

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(22)

    def test_l4_sport_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on L4 source port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].sport = 0x1271

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(10)

    def test_ip_proto_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on the IP protocol."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["IPv6"].nh = 0x7F

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(18)

    def test_tcp_flags_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """Verify that we can match and drop on the TCP flags."""
        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt["TCP"].flags = 0x24

        self.verify_acl_traffic(setup, direction, ptfadapter, pkt, True)
        counters_sanity_check.append(5)


class NdpResponder(BaseHostResponder):
    @pytest.fixture(scope="module")
    def populate_vlan_entries(self, setup, ptfhost, duthosts, rand_one_dut_hostname):
        """Set up the NDP responder utility in the PTF container.

        TODO: We don't currently have NDP support like we do w/ ARP responder, so
        for now we have this stub implementation."""
        def noop():
            pass

        yield noop


class TestBasicAcl(AclIPv6Test, NdpResponder, BasicAclConfiguration):
    """Test Basic functionality of ACL rules (i.e. setup with full update on a running device)."""
    def acl_rules_template(self):
        return os.path.join(TEMPLATE_DIR, ACL_RULES_FULL_TEMPLATE)


class TestIncrementalAcl(AclIPv6Test, NdpResponder, IncrementalAclConfiguration):
    """Test ACL rule functionality with an incremental configuration.

    Verify that everything still works as expected when an ACL configuration is applied in
    multiple parts.
    """
    def acl_rules_templates(self):
        return [os.path.join(TEMPLATE_DIR, config_file) for config_file in ACL_RULES_PART_TEMPLATES]


@pytest.mark.reboot
class TestAclWithReboot(AclIPv6Test, NdpResponder, BasicAclConfigurationWithReboot):
    """Test ACL rule functionality with a reboot.

    Verify that configuration persists correctly after reboot and is applied properly
    upon startup.
    """
    def acl_rules_template(self):
        return os.path.join(TEMPLATE_DIR, ACL_RULES_FULL_TEMPLATE)


@pytest.mark.port_toggle
class TestAclWithPortToggle(AclIPv6Test, NdpResponder, BasicAclConfigurationWithPortToggle):
    """Test ACL rule functionality after toggling ports.

    Verify that ACLs still function as expected after links flap.
    """
    def acl_rules_template(self):
        return os.path.join(TEMPLATE_DIR, ACL_RULES_FULL_TEMPLATE)
