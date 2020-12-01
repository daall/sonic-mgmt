import logging
import os
import pprint
import pytest
import random
import time

import ptf.testutils as testutils

from abc import ABCMeta, abstractmethod

from tests.common import reboot, port_toggle
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger = logging.getLogger(__name__)

DUT_TMP_DIR = "acl_test_dir"  # Keep it under home dir so it persists through reboot
TEMPLATE_DIR = "acl/templates"


class BaseAclTest(object):
    """Base class for testing ACL rules.

    Subclasses must provide `setup_rules` method to prepare ACL rules for traffic testing.

    They can optionally override `teardown_rules`, which will otherwise remove the rules by
    applying an empty configuration file.
    """

    __metaclass__ = ABCMeta

    ACL_TABLE_TEMPLATE = "acltb_table.j2"

    LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
    LOG_EXPECT_ACL_TABLE_REMOVE_RE = ".*Successfully deleted ACL table.*"

    ACL_COUNTERS_UPDATE_INTERVAL_SECS = 10

    @abstractmethod
    @pytest.fixture(scope="class")
    def table_type(self):
        """Return the type of ACL table to test."""
        pass

    @abstractmethod
    def get_dst_ip(self, direction):
        """Get the default destination IP for the current test."""
        pass

    @abstractmethod
    def tcp_packet(self, setup, direction, ptfadapter):
        """Generate a TCP packet for testing."""
        pass

    @abstractmethod
    def udp_packet(self, setup, direction, ptfadapter):
        """Generate a UDP packet for testing."""
        pass

    @abstractmethod
    def icmp_packet(self, setup, direction, ptfadapter):
        """Generate an ICMP packet for testing."""
        pass

    @abstractmethod
    def expected_mask_routed_packet(self, pkt):
        """Generate the expected mask for a routed packet."""
        pass

    @pytest.fixture(scope="class")
    def acl_table_config(self, duthosts, rand_one_dut_hostname, setup, stage, table_type):
        """Generate ACL table configuration files and deploy them to the DUT.

        Args:
            duthosts: All DUTs belong to the testbed.
            rand_one_dut_hostname: hostname of a random chosen dut to run test.
            setup: Parameters for the ACL tests.
            stage: The ACL stage under test.
            table_type: The type of ACL table under test.

        Returns:
            A dictionary containing the table name and the corresponding configuration file.

        """
        duthost = duthosts[rand_one_dut_hostname]

        acl_table_name = "DATA_{}_{}_TEST".format(stage.upper(), table_type.upper())

        acl_table_vars = {
            "acl_table_name": acl_table_name,
            "acl_table_ports": setup["acl_table_ports"],
            "acl_table_stage": stage,
            "acl_table_type": table_type
        }

        logger.info("ACL table configuration:\n{}".format(pprint.pformat(acl_table_vars)))

        acl_table_config_file = "acl_table_{}.json".format(acl_table_name)
        acl_table_config_path = os.path.join(DUT_TMP_DIR, acl_table_config_file)

        logger.info("Generating DUT config for ACL table \"{}\"".format(acl_table_name))
        duthost.host.options["variable_manager"].extra_vars.update(acl_table_vars)
        duthost.template(
            src=os.path.join(TEMPLATE_DIR, self.ACL_TABLE_TEMPLATE),
            dest=acl_table_config_path
        )

        return {
            "table_name": acl_table_name,
            "config_file": acl_table_config_path
        }

    @pytest.fixture(scope="class")
    def acl_table(self, duthosts, rand_one_dut_hostname, acl_table_config, backup_and_restore_config_db_module):
        """Apply ACL table configuration and remove after tests.

        Args:
            duthosts: All DUTs belong to the testbed.
            rand_one_dut_hostname: hostname of a random chosen dut to run test.
            acl_table_config: A dictionary describing the ACL table configuration to apply.
            backup_and_restore_config_db_module: A fixture that handles restoring Config DB
                    after the tests are over.

        Yields:
            The ACL table configuration.

        """
        duthost = duthosts[rand_one_dut_hostname]
        table_name = acl_table_config["table_name"]
        config_file = acl_table_config["config_file"]

        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="acl")
        loganalyzer.load_common_config()

        try:
            loganalyzer.expect_regex = [self.LOG_EXPECT_ACL_TABLE_CREATE_RE]
            with loganalyzer:
                logger.info("Creating ACL table from config file: \"{}\"".format(config_file))

                # TODO: Use `config` CLI to create ACL table
                duthost.command("sonic-cfggen -j {} --write-to-db".format(config_file))
        except LogAnalyzerError as err:
            # Cleanup Config DB if table creation failed
            logger.error("ACL table creation failed, attempting to clean-up...")
            duthost.command("config acl remove table {}".format(table_name))
            raise err

        try:
            yield acl_table_config
        finally:
            loganalyzer.expect_regex = [self.LOG_EXPECT_ACL_TABLE_REMOVE_RE]
            with loganalyzer:
                logger.info("Removing ACL table \"{}\"".format(table_name))
                duthost.command("config acl remove table {}".format(table_name))

    @pytest.yield_fixture(scope="class", autouse=True)
    def counters_sanity_check(self, duthosts, rand_one_dut_hostname, acl_table):
        """Validate that the counters for each rule in the rules list increased as expected.

        This fixture yields a list of rule IDs. The test case should add on to this list if
        it is required to check the rule for increased counters.

        After the test cases pass, the fixture will wait for the ACL counters to update and then
        check if the counters for each rule in the list were increased.

        Args:
            duthosts: All DUTs belong to the testbed.
            rand_one_dut_hostname: hostname of a random chosen dut to run test.
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

    def get_src_port(self, setup, direction):
        """Get a source port for the current test."""
        src_ports = setup["downstream_port_ids"] if direction == "downlink->uplink" else setup["upstream_port_ids"]
        return random.choice(src_ports)

    def get_dst_ports(self, setup, direction):
        """Get the set of possible destination ports for the current test."""
        return setup["upstream_port_ids"] if direction == "downlink->uplink" else setup["downstream_port_ids"]

    def verify_acl_traffic(self, setup, direction, ptfadapter, pkt, dropped):
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)

        if dropped:
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))
        else:
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))


class BaseHostResponder(object):
    @pytest.fixture(scope="module")
    def populate_vlan_entries(self, setup, ptfhost, duthosts, rand_one_dut_hostname):
        pass


class AclRuleConfigurationMode(object):
    __metaclass__ = ABCMeta

    FILES_DIR = "acl/files"
    ACL_REMOVE_RULES_FILE = "acl_rules_del.json"

    LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"
    LOG_EXPECT_ACL_RULE_REMOVE_RE = ".*Successfully deleted ACL rule.*"

    @abstractmethod
    def setup_rules(self, dut, acl_table):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        pass

    def post_setup_hook(self, dut, localhost, populate_vlan_entries, tbinfo):
        """Perform actions after rules have been applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_entries: A function to populate ARP/FDB tables for VLAN interfaces.
            tbinfo: Information about the testbed.

        """
        pass

    @pytest.fixture(scope="class", autouse=True)
    def acl_rules(self, duthosts, rand_one_dut_hostname, localhost, setup, acl_table, populate_vlan_entries, tbinfo):
        """Setup/teardown ACL rules for the current set of tests.

        Args:
            duthosts: All DUTs belong to the testbed.
            rand_one_dut_hostname: hostname of a random chosen dut to run test.
            localhost: The host from which tests are run.
            setup: Parameters for the ACL tests.
            acl_table: Configuration info for the ACL table.
            populate_vlan_entries: A function to populate ARP/FDB tables for VLAN interfaces.
            tbinfo: Information about the testbed.

        """
        duthost = duthosts[rand_one_dut_hostname]
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="acl_rules")
        loganalyzer.load_common_config()

        try:
            loganalyzer.expect_regex = [self.LOG_EXPECT_ACL_RULE_CREATE_RE]
            with loganalyzer:
                self.setup_rules(duthost, acl_table)

            self.post_setup_hook(duthost, localhost, populate_vlan_entries, tbinfo)
        except LogAnalyzerError as err:
            # Cleanup Config DB if rule creation failed
            logger.error("ACL table creation failed, attempting to clean-up...")
            self.teardown_rules(duthost)
            raise err

        try:
            yield
        finally:
            loganalyzer.expect_regex = [self.LOG_EXPECT_ACL_RULE_REMOVE_RE]
            with loganalyzer:
                logger.info("Removing ACL rules")
                self.teardown_rules(duthost)

    def teardown_rules(self, dut):
        """Tear down ACL rules once the tests have completed.

        Args:
            dut: The DUT having ACLs applied.

        """
        logger.info("Finished with tests, removing all ACL rules...")

        # Copy empty rules configuration
        dut.copy(src=os.path.join(self.FILES_DIR, self.ACL_REMOVE_RULES_FILE), dest=DUT_TMP_DIR)
        remove_rules_dut_path = os.path.join(DUT_TMP_DIR, self.ACL_REMOVE_RULES_FILE)

        # Remove the rules
        logger.info("Applying \"{}\"".format(remove_rules_dut_path))
        dut.command("config acl update full {}".format(remove_rules_dut_path))


class BasicAclConfiguration(AclRuleConfigurationMode):
    """Test Basic functionality of ACL rules (i.e. setup with full update on a running device)."""

    ACL_RULES_FULL_TEMPLATE = "acltb_test_rules.j2"

    def setup_rules(self, dut, acl_table):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        table_name = acl_table["table_name"]
        dut_conf_file_path = os.path.join(DUT_TMP_DIR, "acl_rules_{}.json".format(table_name))

        logger.info("Generating basic ACL rules config for ACL table \"{}\"".format(table_name))
        dut.template(src=os.path.join(TEMPLATE_DIR, self.ACL_RULES_FULL_TEMPLATE),
                     dest=dut_conf_file_path)

        logger.info("Applying ACL rules config \"{}\"".format(dut_conf_file_path))
        dut.command("config acl update full {}".format(dut_conf_file_path))


class IncrementalAclConfiguration(AclRuleConfigurationMode):
    """Test ACL rule functionality with an incremental configuration.

    Verify that everything still works as expected when an ACL configuration is applied in
    multiple parts.
    """

    ACL_RULES_PART_TEMPLATES = tuple("acltb_test_rules_part_{}.j2".format(i) for i in xrange(1, 3))

    def setup_rules(self, dut, acl_table):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        table_name = acl_table["table_name"]

        logger.info("Generating incremental ACL rules config for ACL table \"{}\""
                    .format(table_name))

        for part, config_file in enumerate(self.ACL_RULES_PART_TEMPLATES):
            dut_conf_file_path = os.path.join(DUT_TMP_DIR, "acl_rules_{}_part_{}.json".format(table_name, part))
            dut.template(src=os.path.join(TEMPLATE_DIR, config_file), dest=dut_conf_file_path)

            logger.info("Applying ACL rules config \"{}\"".format(dut_conf_file_path))
            dut.command("config acl update incremental {}".format(dut_conf_file_path))


class BasicAclConfigurationWithReboot(BasicAclConfiguration):
    """Test ACL rule functionality with a reboot.

    Verify that configuration persists correctly after reboot and is applied properly
    upon startup.
    """

    def post_setup_hook(self, dut, localhost, populate_vlan_entries, tbinfo):
        """Save configuration and reboot after rules are applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_entries: A fixture to populate ARP/FDB tables for VLAN interfaces.
            tbinfo: Information about the testbed.

        """
        dut.command("config save -y")
        reboot(dut, localhost)
        populate_vlan_entries()


class BasicAclConfigurationWithPortToggle(BasicAclConfiguration):
    """Test ACL rule functionality after toggling ports.

    Verify that ACLs still function as expected after links flap.
    """

    def post_setup_hook(self, dut, localhost, populate_vlan_entries, tbinfo):
        """Toggle ports after rules are applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_entries: A fixture to populate ARP/FDB tables for VLAN interfaces.
            tbinfo: Information about the testbed.

        """
        port_toggle(dut, tbinfo)
        populate_vlan_entries()
