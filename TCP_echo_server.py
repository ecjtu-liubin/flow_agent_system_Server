import asyncio
import hashlib
import os
from config import *
import re

user_list = {}  # 存储已连接上的用户


async def connect_other_user(dest_ip, reader, writer):
    dest_ip = re.findall(r'(\d+\.\d+\.\d+\.\d+)$',dest_ip)
    # print(ip_start)
    if len(dest_ip) == 0:
        return False
    try:
        dest = user_list[dest_ip[0]]
        if not dest:
            return False
    except Exception as e:
        pass



async def server_authenticate(reader, writer, secret_key):
    message = os.urandom(32)  # 随机产生 n=32 个字节的字符串
    writer.write(message)
    await writer.drain()
    s = hashlib.sha512()
    s.update(message + secret_key.encode('utf-8'))  # 加密
    digest = s.hexdigest()
    response = await reader.read(1024)
    if digest == response.decode('utf-8'):
        client_addr = writer.get_extra_info('peername')
        user_list[str(client_addr[0])+str(client_addr[1])]=client_addr
        print(user_list)  # 打印已连接的用户，测试用
        print(str(client_addr)+'连接成功')
        return digest
    else:
        writer.write('connection_error'.encode())  # 若连接失败，发送错误信息
        writer.close()


async def handle_echo(reader, writer):
    handle_sock = writer.get_extra_info('socket')
    fd = handle_sock.fileno()
    # print(fd)
    connect_result = await server_authenticate(reader, writer, SECRET_KEY)
    if not connect_result:
        print('连接失败')
        writer.close()
        # handle_sock.close()
        return

    dest_ip = await reader.read(1000)
    find_dest = await connect_other_user(dest_ip.decode(),reader, writer)


    client_addr = writer.get_extra_info('peername')
    while True:
        try:
            data = await reader.read(100)
            # a.send('hahahaa'.encode('utf-8'))
            # print(a)
            message = data.decode()
            # print(client_addr)
            if message == '' or message == 'exit':
                user_list.pop(str(client_addr[0])+str(client_addr[1]))
                # print(user_list)
                print('用户已断开连接:', client_addr)
                writer.close()
                break
            print(f"Received {message!r} from {client_addr!r}")
            print(f"Send: {message!r}", 'liubin')
            writer.write(data)
            await writer.drain()
        except ConnectionResetError:
            user_list.pop(str(client_addr[0]) + str(client_addr[1]))
            print('用户已断开连接:',client_addr)
            writer.close()
            break
    # print("Close the connection")
    # writer.close()


async def main():
    # server对象是异步上下文管理器
    server = await asyncio.start_server(handle_echo, Server_Ip[0], Server_Port[0])
    # server.socket返回内部的服务器套接字列表副本
    addr = server.sockets[0].getsockname()
    print('成功开启服务器:', addr)
    print('等待客户端连接...')
    async with server:
        # 开始接受连接，直到协程被取消。 serve_forever 任务的取消将导致服务器被关闭。
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
