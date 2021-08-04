# 配置文件
import os
import sys
import logging

Server_Ip = [
    '192.168.43.30',  # 手机wlan
    '192.168.137.240',  # tangjian Wlan
]
Server_Port = [
    22222, 9999, 12345, 7890, 12813, 10086
]

Client_Ip = [
    '192.168.43.30',
]
Client_Port = [
    11111, 24374,
]


BASE_DIR = os.path.abspath(os.path.join(os.getcwd(), "../.."))  # 项目根目录
SERVER_DIR = os.path.abspath(os.path.join(os.getcwd(), ".."))  # 上级目录
# print(SERVER_DIR)
ABSOLUTE_DIR = os.path.abspath(os.path.dirname(__file__))  # 当前目录

mycertfile_path = os.path.join(SERVER_DIR, 'server_ssl\mycertfile.pem')
mykeyfile_path = os.path.join(SERVER_DIR, 'server_ssl\mykeyfile.pem')
# print(mycertfile_path)


logging.basicConfig(level=logging.DEBUG,  # 控制台打印的日志级别
                    # filename='server.log',
                    filemode='a',  # 模式，有w和a，w就是写模式，每次都会覆盖之前的日志 a是追加模式，默认a
                    format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'
                    # 日志格式
                    )

SECRET_KEY = 'tangjian_liubin'
