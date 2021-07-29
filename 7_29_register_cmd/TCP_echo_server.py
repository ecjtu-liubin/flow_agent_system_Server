import asyncio
import hashlib
import os
import re
import json
import ssl
import sqlite3
from create_ssl import *
from config import *

user_list = {}  # 存储已连接上的用户
server_list = {}


def create_sqlite_db():
    con = sqlite3.connect("user.db")
    cur = con.cursor()
    sql = "CREATE TABLE IF NOT EXISTS user(id INTEGER PRIMARY KEY,username TEXT,password TEXT,email TEXT)"
    cur.execute(sql)
    return con,cur

def transfer_json(msg, method):
    """字符串与json格式互相转换"""
    if method:
        return json.dumps(msg)
    else:
        return json.loads(msg)


async def connect_dest_server(dest_addr, local_reader, local_writer, dest_reader, dest_writer):
    # dest_ip = re.findall(r'(\d+\.\d+\.\d+\.\d+)$', str(dest_ip))
    # if len(dest_ip) == 0:
    #     return False
    try:
        """ 
        dest = server_list[dest_ip[0]]
        if not dest:
            return False
        dest_addr = dest['addr']  # 目标服务器（客户端）ip，port
        dest_reader = dest['Reader']
        dest_writer = dest['Writer']  # 目标Reader
        """

        local_addr = local_writer.get_extra_info('peername')  # 请求者的ip，port
        request_msg = {'local_addr': local_addr, 'request_addr': dest_addr, 'code': 'Request connection'}  # 给客户端的请求连接信息
        request_msg = transfer_json(request_msg, method=True)
        # print('发送给目标客户端的连接请求'+request_msg)

        dest_writer.write(request_msg.encode())  # 给目标客户端发送连接请求
        await dest_writer.drain()
        # print('----------------------------------------------')
        try:
            ensure_connection = await dest_reader.read(500)
            ensure_connection = transfer_json(ensure_connection.decode(), method=False)

            if ensure_connection['code'] == 'Accept connection':
                try:
                    connect_success = {'local_addr': local_addr, 'request_addr': dest_addr, 'code': 'Ready'}
                    connect_success = transfer_json(connect_success, method=True)
                    local_writer.write(connect_success.encode())
                    await local_writer.drain()
                    print('请求成功：' + str(local_addr) + '正在与' + str(dest_addr) + '通讯...\n')
                    dest = {'addr': dest_addr, 'Reader': dest_reader, 'Writer': dest_writer}
                    return dest

                except Exception as e:
                    print(e)
            else:
                pass

        except Exception as e:
            print(e)
            pass

    except Exception as e:
        print(e)
        pass


def hold_user_info(ip, addr, reader, writer):
    """存储已连接客户端的相关内容"""
    user = {}
    user['addr'], user['Reader'], user['Writer'] = addr, reader, writer
    user_list[ip] = user


def hold_server_info(ip, addr, reader, writer):
    """存储已连接目标服务器（客户端）的相关内容"""
    user = {}
    user['addr'], user['Reader'], user['Writer'] = addr, reader, writer
    server_list[ip] = user


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
        # print('打印已连接的用户'+str(user_list))  # 打印已连接的用户，测试用
        print('\n客户端：' + str(client_addr) + '连接成功\n')
        return digest
    else:
        writer.write('connection_error'.encode())  # 若连接失败，发送错误信息
        writer.close()


async def user_login(reader,writer):
    account = await reader.read(1024)
    account = transfer_json(account.decode(),False)
    sql = "select * from user where username = '{}' and password = '{}'".format(account['username'],account['password'])
    try:
        cur.execute(sql)
        search_result = cur.fetchall()
    except sqlite3.OperationalError:
        search_result = False
    # if account['username']== 'liubin' and account['password'] == '123':
    if search_result:
        print('\n用户'+account['username']+'登陆成功！\n')
        writer.write('Login Success'.encode())
        await writer.drain()
        return True
    else:
        writer.write('Need Email'.encode())
        await writer.drain()
        email = await reader.read(1024)
        sql = "insert into user(username,password,email) values ('{}','{}','{}')".format(
                str(account['username']),str(account['password']),str(email.decode()))
        # print(sql)
        try:
            cur.execute(sql)
            con.commit()
            print('\n用户' + account['username'] + '注册成功！\n')
            writer.write('Register Success'.encode())
            await writer.drain()
            return True
        except Exception as e:
            writer.write('Register Fail'.encode())
            await writer.drain()
            return False
    # else:
    #     pass



async def test():
    print('test start')
    await asyncio.sleep(1)
    print('test end')


async def handle_echo(reader, writer):
    client_addr = writer.get_extra_info('peername')
    connect_result = await server_authenticate(reader, writer, SECRET_KEY)  # 用户合法性验证
    if not connect_result:
        print('客户端：' + str(client_addr) + '连接失败')
        writer.close()
        # handle_sock.close()
        return
    try:
        login_result = await user_login(reader,writer)
        if not login_result:
            user_list.pop(str(client_addr[0]) + str(client_addr[1]))
            print('已断开用户连接:', client_addr)
            writer.close()
            return
    except ConnectionResetError:
        user_list.pop(str(client_addr[0]) + str(client_addr[1]))
        print('用户已断开连接:', client_addr)
        writer.close()
        return


    l_reader, l_writer = await asyncio.open_connection(Client_Ip[0], Client_Port[0])
    server_addr = l_writer.get_extra_info('peername')
    server_addr_str = str(server_addr[0]) + str(server_addr[1])
    hold_server_info(server_addr_str, server_addr, l_reader, l_writer)  # 将处理目标客户端（服务器）的请求信息存起来
    # print(server_list)

    try:
        dest_ip = await reader.read(100)  # 首先需要得到客户端的请求ip
        dest_ip = dest_ip.decode()
        dest_ip = server_addr  # 此处设置默认连接server_addr

        print('正在请求：' + str(client_addr) + '请求目的ip:' + str(dest_ip))
        find_dest = await connect_dest_server(dest_ip, reader, writer, l_reader, l_writer)

        if find_dest:
            s_reader = find_dest['Reader']
            s_writer = find_dest['Writer']
            while True:
                data = await reader.read(100)
                message = data.decode()
                if message == 'alive':
                    writer.write(data)
                    print('心跳响应' + message)
                # print(client_addr)
                if message == '' or message == 'exit':
                    user_list.pop(str(client_addr[0]) + str(client_addr[1]))
                    # print(user_list)
                    print('用户已断开连接:', client_addr)
                    writer.close()
                    break

                s_writer.write(data)
                await s_writer.drain()
                print(str(client_addr) + '正在给' + str(server_addr) + '发送信息：' + data.decode())
                try:
                    re_msg = await s_reader.read(1024)
                    print('已收到' + str(server_addr) + '的回复：\n' + re_msg.decode())
                    try:
                        writer.write(re_msg)
                        await writer.drain()
                        print('成功给' + str(client_addr) + '发送回复：\n' + re_msg.decode())
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)


    except ConnectionResetError:
        user_list.pop(str(client_addr[0]) + str(client_addr[1]))
        print('用户已断开连接:', client_addr)
        writer.close()
    # print("Close the connection")
    # writer.close()
    except ssl.SSLError as e:
        pass


async def get_general_control():
    reader, writer = await asyncio.open_connection(Operat_server_IP[0], Operat_server_Port[0])
    while True:
        cmd = await reader.read(100)
        cmd = cmd.decode()
        if cmd == '1':
            user_info = []
            for user in user_list:
                user_info.append(user_list[user]['addr'])
            re_cmd = transfer_json(user_info, True)
            # print(re_cmd)
            writer.write(re_cmd.encode())
            await writer.drain()
        if cmd == '2':
            for user in user_list:
                try:
                    user_writer = user_list[user]['Writer']
                    print('已断开用户连接:', user_list[user]['addr'])
                    user_writer.close()
                except Exception as e:
                    print(e)
            user_list.clear()
            writer.write('-----全部关闭成功-----'.encode())
            await writer.drain()


async def main():
    ssl_server = creat_server_ssl()
    server = await asyncio.start_server(handle_echo, Server_Ip[0], Server_Port[0], ssl=ssl_server)
    # server.socket返回内部的服务器套接字列表副本
    addr = server.sockets[0].getsockname()
    print('成功开启服务器:', addr)
    print('等待客户端连接...\n')

    try:
        await get_general_control()
    except Exception as e:
        pass

    async with server:
        # 开始接受连接，直到协程被取消。 serve_forever 任务的取消将导致服务器被关闭。
        await server.serve_forever()


if __name__ == '__main__':
    con,cur = create_sqlite_db()
    asyncio.run(main())
