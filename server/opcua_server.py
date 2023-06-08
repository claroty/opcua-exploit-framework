import asyncio
import logging

# asyncua==1.0.1
from asyncua import Server, ua
from asyncua.common.methods import uamethod


OPC_URI = "http://claory.com"
OPC_ENDPOINT = "opc.tcp://10.51.0.32:13337/claroty"
OPC_NAME = "Claroty OPC-PWN Server"

OPC_OBJECT_NAME = "SecretObj"
OPC_VAR_NAME = "SecretVar"
OPC_VAR_VALUE = "XSS GOES HERE"

ALLOW_VAR_TO_BE_WRITABLE = False
IS_DEBUG = False
LOGGING_LEVEL = logging.INFO #logging.DEBUG

async def main():
    _logger = logging.getLogger(__name__)

    # Setup server
    server = Server()
    await server.init()
    server.set_endpoint(OPC_ENDPOINT)
    server.name = OPC_NAME

    # Setup namespace
    idx = await server.register_namespace(OPC_URI)

    # Populate namespace with our obj/var
    #   NOTE: server.nodes, contains links to very common nodes like objects and root
    myobj = await server.nodes.objects.add_object(idx, OPC_OBJECT_NAME)
    myvar = await myobj.add_variable(idx, OPC_VAR_NAME, OPC_VAR_VALUE)

    # Should myvar to be writable by clients ?
    if ALLOW_VAR_TO_BE_WRITABLE:
        await myvar.set_writable()

    _logger.info("Starting main loop")
    async with server:
        while True:
            await asyncio.sleep(1)
            _logger.info("Still alive..")


if __name__ == "__main__":
    logging.basicConfig(level=LOGGING_LEVEL)
    asyncio.run(main(), debug=IS_DEBUG)