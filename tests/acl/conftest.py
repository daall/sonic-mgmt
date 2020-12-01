import json
import logging
import os
import pprint
import pytest
import random

from collections import defaultdict

from tests.acl.acl_test_constants import (
    DUT_TMP_DIR,
    DOWNSTREAM_DST_IP,
    DOWNSTREAM_IP_TO_ALLOW,
    DOWNSTREAM_IP_TO_BLOCK,
    VLAN_BASE_MAC_PATTERN,
    TEMPLATE_DIR,
    ACL_TABLE_TEMPLATE,
    LOG_EXPECT_ACL_TABLE_CREATE_RE,
    LOG_EXPECT_ACL_TABLE_REMOVE_RE
)

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger = logging.getLogger(__name__)

pytest_plugins = ("tests.common.fixtures.duthost_utils")


@pytest.fixture(scope="module")
def setup(duthosts, rand_one_dut_hostname, tbinfo, ptfadapter):
    """Gather all required test information from DUT and tbinfo.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        tbinfo: A fixture to gather information about the testbed.

    Yields:
        A Dictionary with required test information.

    """
    duthost = duthosts[rand_one_dut_hostname]

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # Get the list of upstream/downstream ports
    downstream_ports = []
    upstream_ports = []
    downstream_port_ids = []
    upstream_port_ids = []

    topo = tbinfo["topo"]["type"]
    for interface, neighbor in mg_facts["minigraph_neighbors"].items():
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if (topo == "t1" and "T0" in neighbor["name"]) or (topo == "t0" and "Server" in neighbor["name"]):
            downstream_ports.append(interface)
            downstream_port_ids.append(port_id)
        elif (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]):
            upstream_ports.append(interface)
            upstream_port_ids.append(port_id)

    # Get the list of LAGs
    port_channels = mg_facts["minigraph_portchannels"]

    # TODO: We should make this more robust (i.e. bind all active front-panel ports)
    acl_table_ports = []

    if topo == "t0" or tbinfo["topo"]["name"] in ("t1", "t1-lag"):
        acl_table_ports += downstream_ports

    if topo == "t0" or tbinfo["topo"]["name"] in ("t1-lag", "t1-64-lag", "t1-64-lag-clet"):
        acl_table_ports += port_channels
    else:
        acl_table_ports += upstream_ports

    vlan_ports = []

    if topo == "t0":
        vlan_ports = [mg_facts["minigraph_ptf_indices"][ifname]
                      for ifname
                      in mg_facts["minigraph_vlans"].values()[0]["members"]]

    host_facts = duthost.setup()["ansible_facts"]

    setup_information = {
        "router_mac": host_facts["ansible_Ethernet0"]["macaddress"],
        "downstream_port_ids": downstream_port_ids,
        "upstream_port_ids": upstream_port_ids,
        "acl_table_ports": acl_table_ports,
        "vlan_ports": vlan_ports,
        "topo": topo
    }

    logger.info("Gathered variables for ACL test:\n{}".format(pprint.pformat(setup_information)))

    logger.info("Creating temporary folder \"{}\" for ACL test".format(DUT_TMP_DIR))
    duthost.command("mkdir -p {}".format(DUT_TMP_DIR))

    yield setup_information

    logger.info("Removing temporary directory \"{}\"".format(DUT_TMP_DIR))
    duthost.command("rm -rf {}".format(DUT_TMP_DIR))


@pytest.fixture(scope="module")
def populate_vlan_arp_entries(setup, ptfhost, duthosts, rand_one_dut_hostname):
    """Set up the ARP responder utility in the PTF container."""
    duthost = duthosts[rand_one_dut_hostname]
    if setup["topo"] != "t0":
        def noop():
            pass

        yield noop

        return  # Don't fall through to t0 case

    addr_list = [DOWNSTREAM_DST_IP, DOWNSTREAM_IP_TO_ALLOW, DOWNSTREAM_IP_TO_BLOCK]

    vlan_host_map = defaultdict(dict)
    for i in range(len(addr_list)):
        mac = VLAN_BASE_MAC_PATTERN.format(i)
        port = random.choice(setup["vlan_ports"])
        addr = addr_list[i]
        vlan_host_map[port][str(addr)] = mac

    arp_responder_conf = {}
    for port in vlan_host_map:
        arp_responder_conf['eth{}'.format(port)] = vlan_host_map[port]

    with open("/tmp/from_t1.json", "w") as ar_config:
        json.dump(arp_responder_conf, ar_config)
    ptfhost.copy(src="/tmp/from_t1.json", dest="/tmp/from_t1.json")

    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": "-e"})
    ptfhost.template(src="templates/arp_responder.conf.j2",
                     dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread && supervisorctl update")
    ptfhost.shell("supervisorctl restart arp_responder")

    def populate_arp_table():
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")

        for addr in addr_list:
            duthost.command("ping {} -c 3".format(addr), module_ignore_errors=True)

    populate_arp_table()

    yield populate_arp_table

    logging.info("Stopping ARP responder")
    ptfhost.shell("supervisorctl stop arp_responder")

    duthost.command("sonic-clear fdb all")
    duthost.command("sonic-clear arp")


@pytest.fixture(scope="module", params=["ingress", "egress"])
def stage(request, duthosts, rand_one_dut_hostname):
    """Parametrize tests for Ingress/Egress stage testing.

    Args:
        request: A fixture to interact with Pytest data.
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.

    Returns:
        str: The ACL stage to be tested.

    """
    duthost = duthosts[rand_one_dut_hostname]

    # FIXME: We can't use pytest_require in a conftest file b/c pytest thinks it's a hook function
    # This change touches a lot of files, so we'll do it manually here and fix the function in
    # a separate PR
    if request.param == "egress" and duthost.facts["asic_type"] in ("broadcom"):
        pytest.skip("Egress ACLs are not currently supported on \"{}\" ASICs".format(duthost.facts["asic_type"]))

    return request.param


@pytest.fixture(scope="module")
def acl_table_config(duthosts, rand_one_dut_hostname, setup, stage):
    """Generate ACL table configuration files and deploy them to the DUT.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        setup: Parameters for the ACL tests.
        stage: The ACL stage under test.

    Returns:
        A dictionary containing the table name and the corresponding configuration file.

    """
    duthost = duthosts[rand_one_dut_hostname]
    stage_to_name_map = {
        "ingress": "DATA_INGRESS_TEST",
        "egress": "DATA_EGRESS_TEST"
    }

    acl_table_name = stage_to_name_map[stage]

    acl_table_vars = {
        "acl_table_name": acl_table_name,
        "acl_table_ports": setup["acl_table_ports"],
        "acl_table_stage": stage,
        "acl_table_type": "L3"
    }

    logger.info("ACL table configuration:\n{}".format(pprint.pformat(acl_table_vars)))

    acl_table_config_file = "acl_table_{}.json".format(acl_table_name)
    acl_table_config_path = os.path.join(DUT_TMP_DIR,  acl_table_config_file)

    logger.info("Generating DUT config for ACL table \"{}\"".format(acl_table_name))
    duthost.host.options["variable_manager"].extra_vars.update(acl_table_vars)
    duthost.template(
        src=os.path.join(TEMPLATE_DIR, ACL_TABLE_TEMPLATE),
        dest=acl_table_config_path
    )

    return {
        "table_name": acl_table_name,
        "config_file": acl_table_config_path
    }


@pytest.fixture(scope="module")
def acl_table(duthosts, rand_one_dut_hostname, acl_table_config, backup_and_restore_config_db_module):
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
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
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
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_REMOVE_RE]
        with loganalyzer:
            logger.info("Removing ACL table \"{}\"".format(table_name))
            duthost.command("config acl remove table {}".format(table_name))
