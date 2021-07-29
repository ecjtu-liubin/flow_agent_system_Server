import asyncio
import hashlib
import os
import json
import func_timeout

from config import *
from create_ssl import *


def transfer_json(msg, method):
    """字符串与json格式互相转换"""
    if method:
        return json.dumps(msg)
    else:
        return json.loads(msg)


async def client_authenticate(reader, writer, secret_key):
    message = await reader.read(1024)
    s = hashlib.sha512()
    s.update(message + secret_key.encode('utf-8'))  # 加密
    digest = s.hexdigest()
    writer.write(digest.encode())
    await writer.drain()


async def user_login(reader,writer):
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


# async def alive(reader, writer):
#     a = 0
#     while True:
#         try:
#             await asyncio.sleep(4)
#             a += 1
#             message = "alive"
#             writer.write(message.encode())
#             await writer.drain()
#             print(message)
#             msg = await reader.read(10)
#             print(msg)
#         except Exception as e:
#             print("发送失败!!")
#             writer.close()


async def tcp_echo_client():
    try:
        ssl_client = create_client_ssl()
        reader, writer = await asyncio.open_connection(Server_Ip[0], Server_Port[0],ssl=ssl_client)
        await client_authenticate(reader, writer, SECRET_KEY)

        login_result = await user_login(reader,writer)
        if not login_result:
            print("请求登陆失败！")
            raise ConnectionResetError

        local_addr = writer.get_extra_info('sockname')
        dest = input("请输入要连接的ip:")
        dest = '192.168.43.3034812'
        writer.write(dest.encode())
        await writer.drain()
        ensure_dest = await reader.read(100)  # 接受代理服务器转发回复的确认消息
        ensure_dest = transfer_json(ensure_dest.decode(),False)
        dest_addr = str(ensure_dest['request_addr'])
        if ensure_dest['code'] == 'Ready':
            # msg = b'this is the first message'
            print('与'+dest_addr+'成功建立连接')
            while True:
                msg = input('请输入要发送的内容：')
                if  msg == 'exit':
                    writer.close()
                    print('已断开与服务器的连接！')
                    break
                writer.write(msg.encode())
                await writer.drain()
                # print('发送给'+dest_addr+'的消息：'+msg)
                try:
                    re_msg =await reader.read(1024)
                    if re_msg.decode()== '':
                        writer.close()
                        print('与服务器的连接已断开！')
                        break
                    # print(len(re_msg.decode()))
                    print('收到回复内容:\n'+re_msg.decode())
                except Exception as e:
                    print(e)
    except json.decoder.JSONDecodeError:
        print('与服务器的连接已断开！')
    except ConnectionResetError:
        print('与服务器的连接已断开！')
asyncio.run(tcp_echo_client())
