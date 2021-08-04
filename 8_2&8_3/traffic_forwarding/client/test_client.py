import asyncio
import hashlib
import json
import ssl
from config.config import *
from asyncio import ensure_future
import logging

flag = 1  #解决发心跳包和用户发数据时同时读问题

# 发送心跳包
async def heartbeat(reader, writer):
    while True:
            await asyncio.sleep(20)
            if writer.get_extra_info("peername")==None:
                print("服务器已断开...")
                logging.info("服务器已断开...")
                writer.close()
                print("关闭连接...")
                logging.info("关闭连接...")
                break
            else:
                print(f"发送：Heart beat!")
                print(f"{writer.get_extra_info('sockname')}----->{writer.get_extra_info('peername')}")
                logging.info(f"发送心跳包{writer.get_extra_info('sockname')}----->{writer.get_extra_info('peername')}")
                writer.write('Heart beat!'.encode())
                await writer.drain()
                if flag == 1:
                    data = await reader.read(1024)
                    print(f"来自：{writer.get_extra_info('peername')}的{data.decode()}响应")
                    logging.info(f"来自：{writer.get_extra_info('peername')}的{data.decode()}响应")
                    print(f"{writer.get_extra_info('peername')}----->{writer.get_extra_info('sockname')}")
                    #logging.info(f"{writer.get_extra_info('peername')}----->{writer.get_extra_info('sockname')})


async def port_transmit_other(r, w):
    "端口流量转发"
    while True:
        try:
            data = await r.read(1024)
            data = data.decode()
            print('接受到端口流量数据：'+ data)
            print(f"{writer}----->{writer1}")
            logging.info(f"端口流量数据：{writer}----->{writer1}")
            if data == '' or data == 'exit':
                break
            w.write(data.encode())
            await w.drain()
            print('转发至代理服务器：'+data)
            print(f"{r_writer.get_extra_info('sockname')}----->{r_writer.get_extra_info('peername')}")
            logging.info(f"转发数据{r_writer.get_extra_info('sockname')}----->{r_writer.get_extra_info('peername')}")
        except ConnectionResetError:
            local_writer.close()
            await local_writer.wait_closed()
            logging.warning("用户已退出")


    # asyncio.ensure_future(port_transmit_other(l_reader, r_writer))
    # asyncio.ensure_future(port_transmit_server(r_reader, l_writer))
    # #转发数据时需要用到端口信息
    # global writer, writer1
    # writer = l_writer.get_extra_info('peername')
    # writer1 = l_writer.get_extra_info('sockname')

async def port_transmit_server(r, w):
#接受目标服务器发来的信息并转发
    while True:
        try:
            data = await r.read(1024)
            data = data.decode()
            print('收到回复：\n'+data)
            print(f"{r_writer.get_extra_info('peername')}----->{r_writer.get_extra_info('sockname')}")
            logging.info(f"收到回复{r_writer.get_extra_info('peername')}----->{r_writer.get_extra_info('sockname')}")

            if data == '' or data == 'exit':
                logging.info("断开连接...")
                break
            if data == 'Heart beat!':
                print(f"来自：{r_writer.get_extra_info('peername')}的{data}响应")
                logging.info(f"来自：{r_writer.get_extra_info('peername')}的{data}响应   \
{r_writer.get_extra_info('peername')}----->{r_writer.get_extra_info('sockname')}")
                print(f"{r_writer.get_extra_info('peername')}----->{r_writer.get_extra_info('sockname')}")
                continue
            w.write(data.encode())
            print('转发回复：\n'+data)
            print(f"{w.get_extra_info('sockname')}----->{writer}")
        except Exception as e:
            pass


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
    """ssl"""
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.options |= ssl.OP_NO_TLSv1
    ssl_ctx.options |= ssl.OP_NO_TLSv1_1
    ssl_ctx.load_cert_chain(certfile='./client_ssl./mycertfile.pem', keyfile='./client_ssl./mykeyfile.pem')
    ssl_ctx.load_verify_locations(cafile='./client_ssl./mycertfile.pem')
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    return ssl_ctx


async def tcp_client():
    global r_reader, r_writer
    try:
        ssl_client = create_client_ssl()
        r_reader, r_writer = await asyncio.open_connection(Server_Ip[0], Server_Port[0], ssl=ssl_client)
        await client_authenticate(r_reader, r_writer, SECRET_KEY)
        login_result = await user_login(r_reader, r_writer)
        if not login_result:
            print("请求登陆失败！")
            raise ConnectionResetError

        dest = input("请输入要连接的ip:")  # 可选择要连接的目标服务器
        dest = '192.168.43.3034812'
        r_writer.write(dest.encode())
        await r_writer.drain()
        ensure_dest = await r_reader.read(100)  # 接受代理服务器转发回复的确认消息
        print(ensure_dest)
        ensure_dest = transfer_json(ensure_dest.decode(), False)
        dest_addr = str(ensure_dest['request_addr'])
        if ensure_dest['code'] == 'Ready':
            print(f"{r_writer.get_extra_info('sockname')}与{ dest_addr}成功建立连接")
            ensure_future(heartbeat(r_reader, r_writer))
            await server()
            # ensure_future(io_copy(l_reader, r_writer))
            # ensure_future(io_copy(r_reader, l_writer))
        elif ensure_dest['code'] == 'No':
            print("请求连接" + dest_addr + '失败！')
            r_writer.close()
            print('与服务器的连接已断开！')
    except ConnectionRefusedError:
        logging.info("目标服务器未开启...请重试")
        print("目标服务器未开启...请重试")
    except json.decoder.JSONDecodeError:
        print('与服务器的连接已断开！')
    except ConnectionResetError:
        print('与服务器的连接已断开！')
        logging.info("与服务器的连接已断开")
    except RuntimeError as e:
        pass
    except BaseException:
        print(1)

async def handle(l_reader, l_writer):
    global flag, local_writer
    local_writer=l_writer
    flag = 0
    asyncio.ensure_future(port_transmit_other(l_reader, r_writer))
    asyncio.ensure_future(port_transmit_server(r_reader, l_writer))
    #转发数据时需要用到端口信息
    global writer, writer1
    writer = l_writer.get_extra_info('peername')
    writer1 = l_writer.get_extra_info('sockname')

async def server():
    server = await asyncio.start_server(handle, Server_Ip[0], 9999)
    # server.socket返回内部的服务器套接字列表副本
    addr = server.sockets[0].getsockname()
    # logging.debug('成功开启服务器',addr)
    print('成功开启服务器:', addr)
    print('等待用户使用...\n')

    async with server:
        # 开始接受连接，直到协程被取消。 serve_forever 任务的取消将导致服务器被关闭。
        await server.serve_forever()




if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG,  # 控制台打印的日志级别
                        filename='client.log',
                        # encoding='utf-8',
                        filemode='a',  ##模式，有w和a，w就是写模式，每次都会重新写日志，覆盖之前的日志
                        # a是追加模式，默认如果不写的话，就是追加模式
                        format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'
                        # 日志格式
                        )
    asyncio.run(tcp_client())






