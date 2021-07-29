import asyncio
from config import Operat_server_IP,Operat_server_Port

async def handle_echo(reader, writer):

    addr = writer.get_extra_info('peername')
    while True:
        print('(1):获取所有在线客户端\n(2):关闭所有客户端连接')
        cmd =input('输入执行命令：').encode()
        writer.write(cmd)
        await writer.drain()
        re_cmd = await reader.read(1024)
        message = re_cmd.decode()
        print(message)


async def main():
    server = await asyncio.start_server(handle_echo, Operat_server_IP[0],Operat_server_Port[0])

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())