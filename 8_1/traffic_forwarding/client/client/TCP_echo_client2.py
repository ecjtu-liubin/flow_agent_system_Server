import asyncio
import hashlib
import json
import ssl
from asyncio import ensure_future
from xmlrpc.client import ServerProxy
from config.config import *


def transfer_json(msg, method):
    """字符串与json格式互相转换"""
    if method:
        return json.dumps(msg)
    else:
        return json.loads(msg)


async def client_authenticate(reader, writer, secret_key):
    """客户端认证"""
    message = await reader.read(1024)
    s = hashlib.sha512()
    s.update(message + secret_key.encode('utf-8'))  # 加密
    digest = s.hexdigest()
    writer.write(digest.encode())
    await writer.drain()


async def user_login(reader,writer):
    """用户认证与注册"""
    username = input("请输入用户名：")
    password = input("请输入密码：")
    account = {'username':username,'password':password}
    account = transfer_json(account,True)
    writer.write(account.encode())
    await writer.drain()
    ensure_account = await reader.read(1024)
    ensure_account = ensure_account.decode()
    if ensure_account == 'Login Success':
        print('-----用户登陆成功！-----')
        return True
    elif ensure_account == 'Need Email':
        email = input("请输入注册的邮箱地址：")
        writer.write(email.encode())
        await writer.drain()
        ensure_register = await reader.read(1024)
        ensure_register = ensure_register.decode()
        if ensure_register == 'Register Success':
            print('-----用户注册成功！-----')
            return True
        else:
            print("-----用户注册失败！-----")
            return False
    else:
        return False


def create_client_ssl():
    """生成ssl"""
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.options |= ssl.OP_NO_TLSv1
    ssl_ctx.options |= ssl.OP_NO_TLSv1_1
    ssl_ctx.load_cert_chain(certfile='./client_ssl./mycertfile.pem', keyfile='./client_ssl./mykeyfile.pem')
    ssl_ctx.load_verify_locations(cafile='./client_ssl./mycertfile.pem')
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    return ssl_ctx


def send_rule(rpc_port):
    ident = input("请输入ident:")
    src_ip = input("请输入src_ip:")
    src_port = input("请输入src_port:")
    dst_ip = input("请输入dst_ip:")
    dst_port = input("请输入dst_port:")
    server = ServerProxy("http://localhost:{}".format(rpc_port))  # 初始化服务器
    rule = {'ident': ident, 'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port}
    rule_json = json.dumps(rule)
    rsl = server.set_rule(rule_json)  # 调用函数并传参 print ()
    return rsl


async def handle_func(l_reader, l_writer):
    asyncio.ensure_future(port_transmit_other(l_reader, writer))
    asyncio.ensure_future(port_transmit_server(reader, l_writer))


async def port_transmit_other(r, w):
    "端口流量转发"
    while True:
        try:
            data = await r.read(1024)
            data = data.decode()
            print('接受到端口流量数据：'+ data)
            if data == '' or data == 'exit':
                break
            w.write(data.encode())
            await w.drain()
            print('转发至代理服务器：'+data)
        except ConnectionResetError:
            print('与服务器的连接已断开！')
            break


async def port_transmit_server(r, w):
    "接受回复"
    while True:
        try:
            data = await r.read(1024)
            data = data.decode()
            if data == '' or data == 'exit':
                print('与服务器的连接已断开！')
                break
            if data == 'Heart beat!':
                continue
            print('收到回复：' + data)
            w.write(data.encode())
            print('转发回复：'+data)
        except SystemExit:
            break
        except Exception as e:
            print('与服务器的连接已断开！')
            break


async def heartbeat(reader, writer):
    while True:
        try:
            await asyncio.sleep(10)
            if writer.get_extra_info('sockname') is None:
                break
            print(f"发送：Heart beat!")
            print(f"{writer.get_extra_info('sockname')}----->{writer.get_extra_info('peername')}")
            writer.write('Heart beat!'.encode())
            await writer.drain()
        except ConnectionResetError:
            break


async def tcp_echo_client():
    """主函数"""
    global reader, writer
    try:
        ssl_client = create_client_ssl()
        reader, writer = await asyncio.open_connection(Server_Ip[0], Server_Port[0],ssl=ssl_client)
        await client_authenticate(reader, writer, SECRET_KEY)

        login_result = await user_login(reader,writer)
        if not login_result:
            print("请求登陆失败！")
            raise ConnectionResetError

        rpc_port = await reader.read(100)  # 获取rpc服务器绑定的端口号
        rpc_port = int(rpc_port.decode())
        config_rule = send_rule(rpc_port)  # 开始客户端规则配置
        if not config_rule:
            pass

        ensure_dest = await reader.read(100)  # 接受代理服务器转发回复的确认消息
        ensure_dest = transfer_json(ensure_dest.decode(),False)
        dest_addr = str(ensure_dest['request_addr'])
        if ensure_dest['code'] == 'Ready':
            print('与'+dest_addr+'成功建立连接')

            re_rule_json = await reader.read(1024)
            re_rule = json.loads(re_rule_json.decode())
            ident, src_ip, src_port, dst_ip, dst_port = \
                re_rule['ident'], re_rule['src_ip'], re_rule['src_port'], re_rule['dst_ip'], re_rule['dst_port'],

            ensure_future(heartbeat(reader, writer))

            src_ip = '127.0.0.1'
            src_port = 12393
            server = await asyncio.start_server(handle_func, src_ip, int(src_port))
            addr = server.sockets[0].getsockname()
            print('已开启本地端口{}流量转发...\n'.format(addr[1]))
            async with server:
                await server.serve_forever()

        elif ensure_dest['code'] == 'No':
            print("请求连接"+dest_addr+'失败！')
            writer.close()
            print('与服务器的连接已断开！')

    except json.decoder.JSONDecodeError:
        print('与服务器的连接已断开！')
    except ConnectionResetError:
        print('与服务器的连接已断开！')
    except RuntimeError as e:
        pass


def start_connect():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


if __name__ == '__main__':
    start_connect()
