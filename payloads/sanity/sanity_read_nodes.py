# Sanity: Read Array of NodeIDs

import datetime

from protocol import *
from config import *

def attack(server_details, num_requests=1):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session()

    # Prepare message
    message_header = opcua.build_opcua_message_header()
    message_body = opcua.build_opcua_message_body(type_id=1, req_id=631)
    message_body += struct.pack("<Q", 0) # Max age
    message_body += struct.pack("<I", 3) # Timestamp to return (3 = Neither)

    # Nodes to read (array of 12 NodeIDs)
    nodes_to_read = bytes.fromhex("0c0000000100b73a05000000ffffffff0000ffffffff0100b93a05000000ffffffff0000ffffffff0100203e05000000ffffffff0000ffffffff0100df3c05000000ffffffff0000ffffffff01001a3d05000000ffffffff0000ffffffff01001e3d05000000ffffffff0000ffffffff0100263d05000000ffffffff0000ffffffff01002a3d05000000ffffffff0000ffffffff005e05000000ffffffff0000ffffffff01002e3c05000000ffffffff0000ffffffff005f05000000ffffffff0000ffffffff01005b0105000000ffffffff0000ffffffff")
    message = message_header + message_body + nodes_to_read

    # Send num_requests times
    print("[-] Sending MSG Request - Read Array of 12 NodeIDs x {} times".format(1))
    opcua.send_recv(message, count=1, should_recv=True)

    # Close connection
    print("[-] Closing connection")
    opcua.close()