import yaml

IPV4_OPEN_CONFIG_CDB_LOOKUP = {
    "source-ip-address": "SRC_IP",
    "destination-ip-address": "DST_IP",
    "protocol": "IP_PROTOCOL"
}

IPV6_OPEN_CONFIG_CDB_LOOKUP = {
    "source-ip-address": "SRC_IPV6",
    "destination-ip-address": "DST_IPV6",
    "protocol": "IP_PROTOCOL"  # TODO: Transition to NEXT_HEADER once SWSS is updated
}

PORT_RANGE_CDB_LOOKUP = {
    "source-port": "L4_SRC_PORT_RANGE",
    "destination-port": "L4_DST_PORT_RANGE"
}

BASIC_OPEN_CONFIG_CDB_LOOKUP = {
    "ethertype": "ETHER_TYPE",
    "dscp": "DSCP",
    "tcp-flags": "TCP_FLAGS",
    "source-port": "L4_SRC_PORT",
    "destination-port": "L4_DST_PORT"
}


def load_acl_rules_config(table_name, rules_file):
    with open(rules_file, "r") as f:
        acl_rules = yaml.safe_load(f)

    rules_config = {"acl_table_name": table_name, "rules": acl_rules}

    return rules_config


def parse_rules_as_config_db(rules, ip_version):
    cdb_rules = []
    for rule in rules:
        cdb_rule = {"qualifiers": {}}
        for qset in rule["qualifiers"].keys():
            for qualifier, value in rule["qualifiers"][qset].items():
                cdb_qualifier = _parse_open_config_qualifier(qualifier, value, ip_version)
                cdb_value = _parse_open_config_value(qualifier, value)
                cdb_rule["qualifiers"].update({cdb_qualifier: cdb_value})

        # TODO: Add support for specifying packet actions
        cdb_rules.append(cdb_rule)

    return cdb_rules


def _parse_open_config_qualifier(qualifier, value, ip_version):
    if qualifier in IPV4_OPEN_CONFIG_CDB_LOOKUP and ip_version == 4:
        return IPV4_OPEN_CONFIG_CDB_LOOKUP[qualifier]

    if qualifier in IPV6_OPEN_CONFIG_CDB_LOOKUP and ip_version == 6:
        return IPV6_OPEN_CONFIG_CDB_LOOKUP[qualifier]

    if qualifier in PORT_RANGE_CDB_LOOKUP and ".." in value:
        return PORT_RANGE_CDB_LOOKUP[qualifier]

    return BASIC_OPEN_CONFIG_CDB_LOOKUP[qualifier]


def _parse_open_config_value(qualifier, value):
    if qualifier in PORT_RANGE_CDB_LOOKUP and ".." in value:
        return value.replace("..", "-")

    if qualifier == "tcp-flags":
        tcp_flags = 0x00

        if "TCP_FIN" in value:
            tcp_flags |= 0x01
        if "TCP_SYN" in value:
            tcp_flags |= 0x02
        if "TCP_RST" in value:
            tcp_flags |= 0x04
        if "TCP_PSH" in value:
            tcp_flags |= 0x08
        if "TCP_ACK" in value:
            tcp_flags |= 0x10
        if "TCP_URG" in value:
            tcp_flags |= 0x20
        if "TCP_ECE" in value:
            tcp_flags |= 0x40
        if "TCP_CWR" in value:
            tcp_flags |= 0x80

        return "0x{:02x}/0x{:02x}".format(tcp_flags, tcp_flags)

    return str(value)
