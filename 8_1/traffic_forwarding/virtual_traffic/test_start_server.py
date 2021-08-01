import asyncio


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', 12391)
    while True:
        message = input("请输入要发送的消息内容：")
        writer.write(message.encode())
        data = await reader.read(100)
        print('收到信息响应：'+data.decode())

asyncio.run(tcp_echo_client())