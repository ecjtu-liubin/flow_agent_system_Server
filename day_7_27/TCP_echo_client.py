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

    # loop = asyncio.get_event_loop()
    # task1 =loop.create_task(alive(reader,writer))
    # tasks.append(task1)


    dest = input("dest_ip:")
    # dest = '192.168.43.3034812'
    writer.write(dest.encode())
    await writer.drain()
    # ensure_dest = await reader.read(100)
    # print(ensure_dest)
    # elif choose == 2:
    #     connect_request = await reader.read(200)
    #     # print(connect_request.decode())
    #     connect_request = transfer_json(connect_request.decode(), False)
    #
    #     print(connect_request['code'])
    #
    #     if connect_request['code'] == 'Request connection':
    #
    #         accept_connection = {'local_addr': local_addr, 'dest_addr': connect_request['local_addr'], 'code': 'Accept connection'}
    #         accept_connection = transfer_json(accept_connection, True)
    #         writer.write(accept_connection.encode())
    #         await writer.drain()
    #
    #         print(type(accept_connection.encode()))
    #         print(accept_connection)
    #         print('已经确认过了')
    #     else:
    #         pass

    # while True:
    #     message = input('Send: ')
    #     writer.write(message.encode())
    #     await writer.drain()
    #     if message == 'exit':
    #         writer.close()
    #         await writer.wait_closed()
    #         break
    #     data = await reader.read(100)
    #     print('Received: ', data.decode())
    #
    # # # print('Close the connection')
    # writer.close()
    # await writer.wait_closed()


# tasks = []
#
# #
# async def main():
#     await asyncio.wait(tasks)
#
# tasks.append(tcp_echo_client())
asyncio.run(tcp_echo_client())
