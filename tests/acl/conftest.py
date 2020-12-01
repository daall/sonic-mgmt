import logging
import pprint
import pytest

from tests.acl.acl_test_base import DUT_TMP_DIR

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
