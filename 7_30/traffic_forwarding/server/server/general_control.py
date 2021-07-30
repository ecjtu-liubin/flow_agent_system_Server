import asyncio
from config.config import Operat_server_IP, Operat_server_Port

async def handle_echo(reader, writer):
    while True:
        print('(1)/(find -all):获取所有在线客户端\n(2)/(break -all):关闭所有客户端连接')
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


def open_control_center():
    asyncio.run(main())


if __name__ == '__main__':
    open_control_center()