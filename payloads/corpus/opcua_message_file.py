# Building OPC UA Message from Files

import datetime
import os

from protocol import *
from config import *

def send_message_from_file(server_details, file_path, num_requests=1):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.session_timeout = 4 * 1000    # Short session
    opcua.requested_lifetime = 4 * 1000 # Short session
    opcua.create_session()

    # Prepare message
    message_header = opcua.build_opcua_message_header()

    with open(file_path, "rb") as f:
        file_data = f.read()

    message_body = b""
    message_body += file_data[:4] # Type ID , Request type
    message_body += OBJECT.build(opcua.auth_id) # Auth token
    message_body += file_data[6:]
    message = message_header + message_body
    print("[-] Sending MSG Request - from file {} x {} times".format(file_path, num_requests))
    opcua.send_recv(message, num_requests, should_recv=False)
    time.sleep(0.01)

    # Close connection
    print("[-] Closing connection")
    try:
        opcua.close()
    except Exception as e:
        pass

# Corpus - shot all corpus samples to a server
def attack_dir(server_details, dir_corpus):
    # Load corpus
    corpus_files = [os.path.join(dir_corpus, f) for f in os.listdir(dir_corpus) if os.path.isfile(os.path.join(dir_corpus, f))]
    for i, corp_path in enumerate(corpus_files):
        print("--------------------")
        print("[-] Corpus {} of {} total files".format(i, len(corpus_files)))
        print(corp_path)
        send_message_from_file(server_details, corp_path, num_requests=1)


# Corpus - shot a single corpus file to a server
def attack_file(server_details, filepath_corpus, num_requests=1):
    send_message_from_file(server_details, filepath_corpus, num_requests=num_requests)



