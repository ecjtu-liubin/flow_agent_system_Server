import asyncio
from config import *


async def handle_echo(reader, writer):
    # data = await reader.read(100)
    # message = data.decode()
    # addr = writer.get_extra_info('peername')
    #
    # print(f"Received {message!r} from {addr!r}")
    #
    # print(f"Send: {message!r}")
    # writer.write(data)
    # await writer.drain()

    print("Close the connection")
    writer.close()

async def main():
    server = await asyncio.start_server(handle_echo, Client_Ip[0], Client_Port[0])

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())



# import asyncio
#
# async def tcp_echo_client(message):
#     reader, writer = await asyncio.open_connection(
#         '127.0.0.1', 8888)
#
#     print(f'Send: {message!r}')
#     writer.write(message.encode())
#
#     data = await reader.read(100)
#     print(f'Received: {data.decode()!r}')
#
#     print('Close the connection')
#     writer.close()
#
# asyncio.run(tcp_echo_client('Hello World!'))