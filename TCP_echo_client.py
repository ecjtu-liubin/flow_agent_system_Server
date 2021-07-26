import asyncio
import hashlib
import os
from config import *


async def client_authenticate(reader,writer, secret_key):
    message = await reader.read(1024)
    s = hashlib.sha512()
    s.update(message + secret_key.encode('utf-8'))  # 加密
    digest = s.hexdigest()
    writer.write(digest.encode())
    await writer.drain()


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection(Server_Ip[0],Server_Port[0])
    await client_authenticate(reader,writer, SECRET_KEY)

    dest = input("dest_ip:")
    writer.write(dest.encode())
    await writer.drain()
    ensure_dest = await reader.read(100)

    while True:
        message = input('Send: ')
        writer.write(message.encode())
        await writer.drain()
        if message == 'exit':
            writer.close()
            await writer.wait_closed()
            break
        data = await reader.read(100)
        print('Received: ', data.decode())

    # # print('Close the connection')
    # writer.close()
    # await writer.wait_closed()

asyncio.run(tcp_echo_client())