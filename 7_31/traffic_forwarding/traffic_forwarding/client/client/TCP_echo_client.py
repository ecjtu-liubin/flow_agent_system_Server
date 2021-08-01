import asyncio
import hashlib
import json
import ssl
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


def send_rule():

    ident = input("请输入ident:")
    src_ip = input("请输入src_ip:")
    src_port = input("请输入src_port:")
    dst_ip = input("请输入dst_ip:")
    dst_port = input("请输入dst_port:")
    server = ServerProxy("http://localhost:12389")  # 初始化服务器
    rule = {'ident': ident, 'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port}
    rule_json = json.dumps(rule)
    rsl = server.set_rule(rule_json)  # 调用函数并传参 print ()
    return rsl


async def tcp_echo_client():
    """主函数"""
    try:
        ssl_client = create_client_ssl()
        reader, writer = await asyncio.open_connection(Server_Ip[0], Server_Port[0],ssl=ssl_client)
        await client_authenticate(reader, writer, SECRET_KEY)

        login_result = await user_login(reader,writer)
        if not login_result:
            print("请求登陆失败！")
            raise ConnectionResetError

        local_addr = writer.get_extra_info('sockname')

        config_rule = send_rule()
        if not config_rule:
            pass

        # TODO 此处开启客户端作为服务器，转发src_ip,src_port 流量

        # dest = input("请输入要连接的ip:")  # 可选择要连接的目标服务器
        # dest = '192.168.43.3034812'
        # writer.write(dest.encode())
        # await writer.drain()
        ensure_dest = await reader.read(100)  # 接受代理服务器转发回复的确认消息
        ensure_dest = transfer_json(ensure_dest.decode(),False)
        dest_addr = str(ensure_dest['request_addr'])
        if ensure_dest['code'] == 'Ready':
            print('与'+dest_addr+'成功建立连接')

            re_rule_json = await reader.read(1024)
            re_rule = json.loads(re_rule_json.decode())
            ident, src_ip, src_port, dst_ip, dst_port = \
                re_rule['ident'], re_rule['src_ip'], re_rule['src_port'], re_rule['dst_ip'], re_rule['dst_port'],
            # print(re_rule)

            while True:
                msg = input('请输入要发送的内容：')
                if msg == 'exit':
                    writer.write(msg.encode())
                    await writer.drain()
                    ensure_exit = await reader.read(100)
                    if ensure_exit.decode() == 'ByeBye':
                        writer.close()
                        print('已断开与服务器的连接！')
                        break
                writer.write(msg.encode())
                await writer.drain()
                try:
                    re_msg =await reader.read(1024)
                    if re_msg.decode() == '':
                        writer.close()
                        print('与服务器的连接已断开！')
                        break
                    print('收到回复内容:\n'+re_msg.decode())
                except Exception as e:
                    print(e)
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
