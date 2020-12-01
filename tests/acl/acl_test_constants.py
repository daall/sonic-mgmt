"""Constants used for running ACL feature tests.

ONLY constants relevant to the tests should be placed here. Generic ACL constants (i.e. the name
of the Config DB "ACL_TABLE" table) should remain in the common.py file for others to access.
"""

DUT_TMP_DIR = "acl_test_dir"  # Keep it under home dir so it persists through reboot
FILES_DIR = "acl/files"
TEMPLATE_DIR = "acl/templates"

ACL_TABLE_TEMPLATE = "acltb_table.j2"
ACL_RULES_FULL_TEMPLATE = "acltb_test_rules.j2"
ACL_RULES_PART_TEMPLATES = tuple("acltb_test_rules_part_{}.j2".format(i) for i in xrange(1, 3))
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"

DEFAULT_SRC_IP = "20.0.0.1"

DOWNSTREAM_DST_IP = "192.168.0.2"
DOWNSTREAM_IP_TO_ALLOW = "192.168.0.4"
DOWNSTREAM_IP_TO_BLOCK = "192.168.0.8"

UPSTREAM_DST_IP = "192.168.128.1"
UPSTREAM_IP_TO_ALLOW = "192.168.136.1"
UPSTREAM_IP_TO_BLOCK = "192.168.144.1"

VLAN_BASE_MAC_PATTERN = "72060001{:04}"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_TABLE_REMOVE_RE = ".*Successfully deleted ACL table.*"
LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"
LOG_EXPECT_ACL_RULE_REMOVE_RE = ".*Successfully deleted ACL rule.*"
