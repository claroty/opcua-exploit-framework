# Sanity: Get info about specific node Ids

from asyncua import Client
import asyncio

def attack(server_details):
    asyncio.run(attack_impl(server_details))


async def attack_impl(server_details, name_space=0, node_id=3875):
    program_type, ip_addr, port, query_string = server_details

    opcua_uri = f"opc.tcp://{ip_addr}:{port}{query_string}"
    opcua_client = Client(opcua_uri)

    async with opcua_client:
        children = await opcua_client.nodes.objects.get_children()
        print(f"[-] Children: {children}")

        node = opcua_client.get_node(f"ns={name_space};i={node_id}")
        node_name = await node.read_display_name()
        print(f"[-] Namespace: {name_space}, NodeID: {node_id}: {node_name.Text}")