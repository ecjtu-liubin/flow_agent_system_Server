import asyncio
import hashlib
import os
from config import *
import re
import json

user_list = {}  # 存储已连接上的用户


def transfer_json(msg, method):
    """字符串与json格式互相转换"""
    if method:
        return json.dumps(msg)
    else:
        return json.loads(msg)


async def connect_other_user(dest_ip, local_reader, local_writer):
    dest_ip = re.findall(r'(\d+\.\d+\.\d+\.\d+)$', dest_ip)
    if len(dest_ip) == 0:
        return False
    try:
        dest = user_list[dest_ip[0]]
        if not dest:
            return False

        dest_addr = dest['addr']  # 目标客户端ip，port
        dest_reader = dest['Reader']  # 目标客户端Reader
        dest_writer = dest['Writer']
        local_addr = local_writer.get_extra_info('sockname')  # 本客户端的ip，port

        request_msg = {'local_addr': local_addr, 'request_addr': dest_addr, 'code': 'Request connection'}  # 给客户端的请求连接信息
        request_msg = transfer_json(request_msg, method=True)
        print('发送给目标客户端的连接请求'+request_msg)

        dest_writer.write(request_msg.encode())  # 给目标客户端发送连接请求
        await dest_writer.drain()

        print('----------------------------------------------')
        try:
            # print(dest_reader)
            ensure_connection = await dest_reader.read(500)
            # print('123')
            # ensure_connection = transfer_json(ensure_connection.decode(), method=False)
            # print(ensure_connection.decode())
        except Exception as e:
            # print(e)
            pass

        if ensure_connection['code'] == 'Accept connection':
            connect_success = {'local_addr': local_addr, 'request_addr': dest_addr, 'code': 'Ready'}
            connect_success = transfer_json(connect_success, method=True)
            local_writer.write(connect_success)
            await local_writer.drain()
        else:
            pass

    except Exception as e:
        pass


def hold_user_info(ip, addr, reader, writer):
    """存储已连接客户端的相关内容"""
    user = {}
    user['addr'], user['Reader'], user['Writer'] = addr, reader, writer
    user_list[ip] = user


async def server_authenticate(reader, writer, secret_key):
    """客户端合法认证"""
    message = os.urandom(32)  # 随机产生 n=32 个字节的字符串
    writer.write(message)
    await writer.drain()
    s = hashlib.sha512()
    s.update(message + secret_key.encode('utf-8'))  # 加密
    digest = s.hexdigest()
    response = await reader.read(1024)
    if digest == response.decode('utf-8'):
        client_addr = writer.get_extra_info('peername')
        client_addr_str = str(client_addr[0]) + str(client_addr[1])  # 拼接ip和port
        hold_user_info(client_addr_str, client_addr, reader, writer)
        # user_list[client_addr_str]=client_addr
        print('打印已连接的用户'+str(user_list))  # 打印已连接的用户，测试用
        print(str(client_addr) + '连接成功')
        return digest
    else:
        writer.write('connection_error'.encode())  # 若连接失败，发送错误信息
        writer.close()


async def test():
    print('test start')
    await asyncio.sleep(1)
    print('test end')


async def handle_echo(reader, writer):
    connect_result = await server_authenticate(reader, writer, SECRET_KEY)  # 用户合法性验证

    l_reader, l_writer = await asyncio.open_connection(Client_Ip[0],Client_Port[0])
    client_addr = l_writer.get_extra_info('peername')
    client_addr_str = str(client_addr[0]) + str(client_addr[1])
    hold_user_info(client_addr_str, client_addr, l_reader, l_writer)  # 将处理目标客户端（服务器）的请求信息存起来
    print(user_list)

    # handle_sock = writer.get_extra_info('socket')
    # fd = handle_sock.fileno()
    # print('文件描述符：'+fd)

    # loop = asyncio.get_event_loop()  # 获取当前事件循环
    # loop.create_task(test())
    # print('当前时间循环：'+loop)

    if not connect_result:
        print('连接失败')
        writer.close()
        # handle_sock.close()
        return

    dest_ip = await reader.read(100)  # 首先需要得到客户端的请求ip
    print('需要得到客户端的请求ip:'+dest_ip.decode())
    find_dest = await connect_other_user(dest_ip.decode(), reader, writer)

    client_addr = writer.get_extra_info('peername')
    if find_dest:
        while True:
            try:
                data = await reader.read(100)
                # a.send('hahahaa'.encode('utf-8'))
                # print(a)
                message = data.decode()
                if message == 'alive':
                    writer.write(data)
                    print('心跳响应'+message)
                # print(client_addr)
                if message == '' or message == 'exit':
                    user_list.pop(str(client_addr[0]) + str(client_addr[1]))
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
                print('用户已断开连接:', client_addr)
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
