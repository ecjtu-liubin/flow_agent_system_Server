import asyncio
import hashlib
import os
from config import *
import json


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


async def alive(reader, writer):
    a = 0
    while True:
        try:
            await asyncio.sleep(4)
            a += 1
            message = "alive"
            writer.write(message.encode())
            await writer.drain()
            print(message)
            msg = await reader.read(10)
            print(msg)
        except Exception as e:
            print("发送失败!!")
            writer.close()


async def tcp_echo_client():

    reader, writer = await asyncio.open_connection(Server_Ip[0], Server_Port[0])
    await client_authenticate(reader, writer, SECRET_KEY)

    local_addr = writer.get_extra_info('sockname')

    dest = input("dest_ip:")
    dest = '192.168.43.3034812'
    writer.write(dest.encode())
    await writer.drain()
    ensure_dest = await reader.read(100)
    ensure_dest = transfer_json(ensure_dest.decode(),False)
    dest_addr = str(ensure_dest['request_addr'])
    if ensure_dest['code'] == 'Ready':
        # msg = b'this is the first message'
        print('与'+dest_addr+'成功建立连接')
        while True:
            msg = input('请输入要发送的内容：')
            writer.write(msg.encode())
            await writer.drain()
            # print('发送给'+dest_addr+'的消息：'+msg)
            try:
                re_msg =await reader.read(1024)
                print('收到回复内容:\n'+re_msg.decode())
            except Exception as e:
                print(e)
    while True:
        pass

asyncio.run(tcp_echo_client())
