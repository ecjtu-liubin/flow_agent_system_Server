import asyncio


async def tcp_echo_client():
    # reader, writer = await asyncio.open_connection('127.0.0.1', 12321)
    reader, writer = await asyncio.open_connection('127.0.0.1',22)

    while True:
        msg = input(">>").strip()  # 输入要发送的信息
        if len(msg) == 0:
            continue  # 判断输入的信息是否为空，如果空，重新输入
        writer.write(msg.encode())
        await writer.drain()  # 发送指令

        receive_data = await reader.read(5120)
        receive_data = receive_data.decode()
        print(receive_data)  # 打印服务器发来的信息

asyncio.run(tcp_echo_client())
