# Configurable Packet Drop Counters Test Plan

## Overview
This test is aimed at confirming that packets that are dropped for different reasons are properly counted and classified. We must also confirm that the user is able to configure debug counters to track categories of packet drops they care about in their network (e.g. a category for "legal" or expected packet drops).

## Scope
- We assume that these packets are already being dropped, this test exists to verify that those drops are being counted and classified correctly.
- This test serves to verify that the configurable drop counters work properly. MMU and L2 corruption related drops are beyond the scope of this test plan.

## Test Cases

These test cases are for the T0 topology. Support for other topologies may be added in the future.

We will provide the option to specify port-level, switch-level, or both types of counters for these tests in order to provide coverage for vendors that support different capabilities.

### Individual Pipeline Drops 

1. Verify that we can count drops for frames where source MAC = destination MAC.
- Create a drop counter L2_TEST with the reason SMAC_EQUALS_DMAC
- Pick an interface on the DUT and send a series of packets where the source MAC = destination MAC
- Verify that L2_TEST = STAT_IF_IN_DISCARDS

(Side note on this test: In manual tests we have found that typically only a small number of these packets actually make it past the fanout and arrive at the DUT. We're not entirely sure why this is at the moment, but this is the reason why we're checking that the counters are equal without accounting for the total number of packets sent. More investigation is needed.)

2. Verify that we can count drops for packets that are configured to be dropped by ACL rules.
- Load a set of ACL rules onto the device where some of the rules DROP the packet and some of the rules ACCEPT the packet
- Create a drop counter ACL_TEST with the reason ACL_ANY
- Pick an interface and send a series of packets that hit a DROP rule
- Verify that ACL_TEST = STAT_IF_IN_DISCARDS
- Pick an interface and send a series of packets that hit a PASS rule
- Verify that ACL_TEST has not changed

3. Verify that we can count drops for packets that have a link-local source IP address (169.254.x.x).
- Create a drop counter SIP_LOCAL_TEST with the season SIP_LINK_LOCAL
- Pick an interface on the DUT and send a series of packets where the source IP is link local
- Verify that SIP_LOCAL_TEST = STAT_IF_IN_DISCARDS

4. Verify that we can count drops for packets that have a link-local destination IP address (169.254.x.x).
- Create a drop counter DIP_LOCAL_TEST with the reason DIP_LINK_LOCAL
- Pick an interface on the DUT and send a series of packets where the destination IP is link local
- Verify that DIP_LOCAL_TEST = STAT_IF_IN_DISCARDS

5. Verify that we can count drops for packets that are intended for a neighbor device where the link is down.
- Setup VLAN neighbors on the PTF server
- Pick an interface that connects the DUT to the PTF server and shut it down on the fanout switch
- Create a drop counter L3_EGRESS_DOWN_TEST with the reason L3_EGRESS_LINK_DOWN
- Pick an interface on the DUT that is up and send a series of packets where the destination is along the interface that was shutdown on the fanout
- Verify that L3_EGRESS_DOWN_TEST = STAT_IF_IN_DISCARDS

6. Verify that packets that hit multiple drop reasons are only counted once.
- Create a drop counter DOUBLE_TEST with SMAC_EQUALS_DMAC, SIP_LINK_LOCAL, and DIP_LINK_LOCAL
- Pick an interface on the DUT that is up and send a series of packets where a 2-3 of the reasons are present on each packet
- Verify that DOUBLE_TEST = STAT_IF_IN_DISCARDS

7. Verify that packets that don't fit any of the configured drop reasons are still counted in the standard drop counters.
- Create a drop counter NOOP_TEST with SMAC_EQUALS_DMAC, SIP_LINK_LOCAL, and DIP_LINK_LOCAL
- Pick an interface on the DUT that is up and send a series of packets where none of the configured drop reasons are present
- Verify that NOOP_TEST = 0
- Verify that STAT_IF_IN_DISCARDS > 0

### Categorizing Pipeline Drops 

8. Verify that we can configure drop counters to include multiple drop categories.
- Load a set of ACL rules onto the device where some of the rules DROP the packet and some of the rules ACCEPT the packet
- Setup VLAN neighbors on the PTF server
- Pick an interface that connects the DUT to the PTF server and shut it down on the fanout switch
- Create a drop counter MULTI_TEST with SMAC_EQUALS_DMAC, SIP_LINK_LOCAL, DIP_LINK_LOCAL, ACL_ANY, and L3_EGRESS_LINK_DOWN
- Pick an interface on the DUT that is up and send a mix of packets that will hit all the different drop reasons
- Verify that MULTI_TEST = STAT_IF_IN_DISCARDS

9. Verify that counts are still accurate in the presence of multiple counters.
- Create a drop counter ALL_DROPS with SMAC_EQUALS_DMAC, SIP_LINK_LOCAL, and DIP_LINK_LOCAL
- Create a drop counter L2_DROPS with SMAC_EQUALS_DMAC
- Pick an interface on the DUT that is up and send a mix of packets that will hit all the different drop reasons
- Verify that ALL_DROPS = STAT_IF_IN_DISCARDS
- Verify that L2_DROPS = ALL_DROPS - the # of link local packets sent

## Improvements
- Add addtional tests for additional drop reasons. At the moment we're only testing a few different drop types because vendor support for this feature is very limited. As adoption grows we will add tests for new drop reasons.
