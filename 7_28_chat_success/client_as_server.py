import asyncio
from config import *
import json
import asyncio

def transfer_json(msg, method):
    """字符串与json格式互相转换"""
    if method:
        return json.dumps(msg)
    else:
        return json.loads(msg)


async def handle_echo(reader, writer):

    local_addr = writer.get_extra_info('sockname')

    connect_request = await reader.read(200)
    # print(connect_request.decode())
    connect_request = transfer_json(connect_request.decode(), False)
    request_addr = str(connect_request['local_addr'])
    request_code = str(connect_request['code'])

    print(request_addr+'正在请求连接：'+request_code)

    if connect_request['code'] == 'Request connection':

        accept_connection = {'local_addr': local_addr, 'dest_addr': connect_request['local_addr'], 'code': 'Accept connection'}
        accept_connection = transfer_json(accept_connection, True)
        writer.write(accept_connection.encode())
        await writer.drain()

        print('与'+request_addr+'成功建立连接')
    else:
        pass

    while True:
        msg = await reader.read(1024)
        print('接受到来自'+request_addr+'的消息：'+msg.decode())

        re_msg = 'response start!\n'+msg.decode()+'\nresponse end!'

        writer.write(re_msg.encode())
        await writer.drain()
        print('回复给'+request_addr+'的消息:\n'+re_msg)

    # print("Close the connection")
    # writer.close()

async def main():
    server = await asyncio.start_server(handle_echo, Client_Ip[0], Client_Port[0])

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
