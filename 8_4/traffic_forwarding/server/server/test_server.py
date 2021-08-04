import asyncio
import hashlib
import re
import os
import json
import ssl
import sqlite3
import concurrent.futures
from config.config import *
from xmlrpc.server import SimpleXMLRPCServer

user_list = {}  # 存储已连接上的用户
server_list = {}
rules = []


def create_sqlite_db():
    "创建用户数据库和表"
    con = sqlite3.connect("user.db")
    cur = con.cursor()
    sql = "CREATE TABLE IF NOT EXISTS user(id INTEGER PRIMARY KEY,username TEXT,password TEXT,email TEXT)"
    cur.execute(sql)
    return con, cur


def transfer_json(msg, method):
    """字符串与json格式互相转换"""
    if method:
        return json.dumps(msg)
    else:
        return json.loads(msg)


async def connect_dest_server(local_reader, local_writer, dst_ip, dst_port):
    """确认连接到目标服务器"""
    try:
        dst_reader, dst_writer = await asyncio.open_connection(dst_ip, dst_port)
    except Exception as e:
        local_writer.write('exit'.encode())
        await local_writer.drain()
        return False

    client_addr = local_writer.get_extra_info('peername')
    dst_addr = dst_writer.get_extra_info('peername')
    dst_addr_str = str(dst_addr[0]) + str(dst_addr[1])
    hold_server_info(dst_addr_str, dst_addr, dst_reader, dst_writer)  # 将处理目标客户端（服务器）的请求信息存起来

    # connect_success = {'local_addr': client_addr, 'request_addr': dst_addr, 'code': 'Ready'}
    # connect_success = transfer_json(connect_success, method=True)
    try:
        # local_writer.write(connect_success.encode())
        # await local_writer.drain()
        logging.info('请求成功：' + str(client_addr) + '正在与' + str(dst_addr) + '通讯...\n')
        dest = {'addr': dst_addr, 'Reader': dst_reader, 'Writer': dst_writer}
        return dest
    except ConnectionResetError:
        logging.info('已断开用户连接:' + client_addr)
        # print('已断开用户连接:', local_addr)
        return False
    except Exception as e:
        print('0', e)


def hold_user_info(ip, addr, reader, writer):
    """存储对应已连接客户端的相关内容"""
    user = {'addr': addr, 'Reader': reader, 'Writer': writer, 'have_config': None}
    user_list[ip] = user


def hold_server_info(ip, addr, reader, writer):
    """存储对应已连接目的服务器的相关内容"""
    user = {'addr': addr, 'Reader': reader, 'Writer': writer}
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
        logging.info('客户端：' + str(client_addr) + '与服务器连接成功')
        # print('客户端：' + str(client_addr) + '连接成功')
        return digest
    else:
        writer.write('connection_error'.encode())  # 若连接失败，发送错误信息
        writer.close()


async def user_login(reader, writer):
    """用户登陆"""
    global search_result, account
    try:
        search_result = None
        account = await reader.read(1024)
        account = transfer_json(account.decode(), False)
        sql = "select * from user where username = '{}' and password = '{}'".format(account['username'],
                                                                                    account['password'])
        cur.execute(sql)
        search_result = cur.fetchall()
    except sqlite3.OperationalError:
        search_result = False
    except ssl.SSLError:
        search_result = False

    if search_result:
        logging.info('用户' + account['username'] + '登陆成功！')
        # print('用户' + account['username'] + '登陆成功！')
        writer.write('Login Success'.encode())
        await writer.drain()
        return True
    else:
        writer.write('Need Email'.encode())
        await writer.drain()
        email = await reader.read(1024)
        verify_email = re.match(r'^[0-9a-zA-Z_]{0,19}@[0-9a-zA-Z]{1,13}\.[com,cn,net]{1,3}(.cn)?$', email.decode())
        if verify_email:
            email = verify_email.group()
            sql = "insert into user(username,password,email) values ('{}','{}','{}')".format(
                str(account['username']), str(account['password']), str(email))
            try:
                cur.execute(sql)
                con.commit()
                logging.info('用户' + account['username'] + '注册成功！')
                # print('用户' + account['username'] + '注册成功！')
                writer.write('Register Success'.encode())
                await writer.drain()
                return True
            except Exception:
                writer.write('Register Fail'.encode())
                await writer.drain()
                return False
        else:
            writer.write('Register Fail'.encode())
            await writer.drain()
            return False


def creat_server_ssl():
    """ssl"""
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.options |= ssl.OP_NO_TLSv1
    ssl_ctx.options |= ssl.OP_NO_TLSv1_1
    ssl_ctx.options |= ssl.OP_SINGLE_DH_USE
    ssl_ctx.options |= ssl.OP_SINGLE_ECDH_USE
    ssl_ctx.load_cert_chain(certfile='./server_ssl/mycertfile.pem', keyfile='./server_ssl/mykeyfile.pem')
    ssl_ctx.load_verify_locations(cafile='./server_ssl/mycertfile.pem')
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    return ssl_ctx


def get_all_client():
    """获取所有在线客户端"""
    user_info = {}
    for user_ip in user_list:
        user_info[user_ip] = {'addr': user_list[user_ip]['addr'], 'have_config': user_list[user_ip]['have_config']}
    user_info_json = json.dumps(user_info)
    return user_info_json


def break_all_client():
    """强制断开所有在线客户端"""
    for user in user_list:
        try:
            user_writer = user_list[user]['Writer']
            user_writer.write('exit'.encode())
            # await user_writer.drain()
            user_writer.close()
            logging.info('已断开用户连接:'+str(user_list[user]['addr']))
            # print('已断开用户连接:', user_list[user]['addr'])
        except Exception as e:
            logging.error('强制断开所有客户端时出错', e)
    user_list.clear()
    return True


def config_user(rule):
    """配置客户端连接规则"""
    user_ip = rule['user_ip']
    rule['ident'] = 'OK'
    # print(user_list)
    user_writer = user_list[user_ip]['Writer']
    rule_json = json.dumps(rule)
    user_writer.write(rule_json.encode())
    user_list[user_ip]['have_config'] = 'OK'
    return True


def RPC_server():
    """开启RPC服务器"""
    global rpc_server
    rpc_server = SimpleXMLRPCServer(('localhost', 12039))  # 初始化
    rpc_server.register_function(get_all_client, )  # 注册函数
    rpc_server.register_function(break_all_client, )  # 注册函数
    rpc_server.register_function(config_user, )  # 注册函数
    try:
        rpc_server.serve_forever()  # 保持等待调用状态

    except OSError:
        logging.error('RPC服务器断开连接')
    return True


async def client_transmit_2_dst(c_reader, c_writer, s_reader, s_writer):
    client_addr = c_writer.get_extra_info('peername')
    server_addr = s_writer.get_extra_info('peername')
    try:
        while True:
            data = await c_reader.read(1024)
            if data == b'Heart beat!':
                c_writer.write(data)
                logging.info('心跳响应' + str(data))
                # print('心跳响应' + message)
                continue
            if data == b'' or data == b'exit':
                user_list.pop(str(client_addr[0]) + str(client_addr[1]))
                logging.info('用户已断开连接:', client_addr)
                # print('用户已断开连接:', client_addr)
                c_writer.close()
                s_writer.close()
                break
            s_writer.write(data)
            # await s_writer.drain()
            logging.info(str(client_addr) + '正在给' + str(server_addr) + '发送信息')
    except Exception:
        pass

async def dst_transmit_2_client(c_reader, c_writer, s_reader, s_writer):
    client_addr = c_writer.get_extra_info('peername')
    server_addr = s_writer.get_extra_info('peername')
    while True:
        re_data = await s_reader.read(5120)
        if re_data == b'':
            break
        logging.info('已收到' + str(server_addr) + '给' + str(client_addr) + '的回复\n')
        c_writer.write(re_data)
        # await c_writer.drain()
        logging.info('成功给' + str(client_addr) + '发送回复：\n')


async def handle_echo(reader, writer):
    # client_addr = writer.get_extra_info('peername')
    # connect_result = await server_authenticate(reader, writer, SECRET_KEY)  # 用户合法性验证
    # if not connect_result:
    #     logging.warning('客户端：' + str(client_addr) + '连接失败')
    #     writer.close()
    #     return
    # try:
    #     login_result = await user_login(reader, writer)
    #     if not login_result:
    #         user_list.pop(str(client_addr[0]) + str(client_addr[1]))
    #         logging.info('已断开用户连接:', client_addr)
    #         writer.close()
    #         return
    # except ConnectionResetError:
    #     user_list.pop(str(client_addr[0]) + str(client_addr[1]))
    #     logging.info('已断开用户连接:', client_addr)
    #     writer.close()
    #     return
    # except ssl.SSLError as e:
    #     return
    client_addr = writer.get_extra_info('peername')
    client_addr_str = str(client_addr[0]) + str(client_addr[1])  # 拼接ip和port
    hold_user_info(client_addr_str, client_addr, reader, writer)

    ident = await reader.read(1024)
    ident = json.loads(ident)
    print(ident)
    if ident['other'] == 'hello':
        writer.write('waiting...'.encode())
        await writer.drain()
    try:
        config_rule = await reader.read(1024)
        config_rule = json.loads(config_rule)
        print(config_rule)
        ident, src_ip, src_port, dst_ip, dst_port = \
            config_rule['ident'], config_rule['src_ip'], config_rule['src_port'], config_rule['dst_ip'], config_rule[
                'dst_port'],
        while True:
            ensure_open_server_connect = await reader.read(1024)
            print(ensure_open_server_connect)
            if ensure_open_server_connect == b'start_server':
                break
            elif ensure_open_server_connect == b'Heart beat!':
                logging.info('心跳响应' + str(ensure_open_server_connect))
                writer.write(ensure_open_server_connect)
            else:
                pass
        find_dest = await connect_dest_server(reader, writer, dst_ip, int(dst_port))
        if find_dest:
            s_reader = find_dest['Reader']
            s_writer = find_dest['Writer']
            asyncio.ensure_future(client_transmit_2_dst(reader, writer, s_reader, s_writer))
            asyncio.ensure_future(dst_transmit_2_client(reader, writer, s_reader, s_writer))
        else:
            logging.warning(str(client_addr) + "请求" + str(dst_ip) + "失败，连接已断开！")
    except Exception:
        return

    # try:
    #     find_dest = await connect_dest_server(reader, writer, dst_ip, dst_port)
    #     if find_dest:
    #         s_reader = find_dest['Reader']
    #         s_writer = find_dest['Writer']
    #         asyncio.ensure_future(client_transmit_2_dst(reader, writer, s_reader, s_writer))
    #         asyncio.ensure_future(dst_transmit_2_client(reader, writer, s_reader, s_writer))
    #     else:
    #         logging.warning(str(client_addr) + "请求" + str(dst_ip) + "失败，连接已断开！")
    # except ConnectionResetError:
    #     writer.close()
    #     user_list.pop(str(client_addr[0]) + str(client_addr[1]))
    #     logging.info('客户端已断开连接:' + str(client_addr))
    # except ssl.SSLError as e:
    #     pass


async def main():
    ssl_server = creat_server_ssl()
    server = await asyncio.start_server(handle_echo, Server_Ip[0], Server_Port[0])
    addr = server.sockets[0].getsockname()
    logging.info('成功开启流量代理服务器:' + str(addr) + '\n等待客户端连接...')
    # print('成功开启流量代理服务器:'+str(addr)+'\n等待客户端连接...')

    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        config_rule = await loop.run_in_executor(pool, RPC_server)

    async with server:
        # 开始接受连接，直到协程被取消。 serve_forever 任务的取消将导致服务器被关闭。
        await server.serve_forever()


def open_agent_server():
    asyncio.run(main())


con, cur = create_sqlite_db()

if __name__ == '__main__':
    open_agent_server()
