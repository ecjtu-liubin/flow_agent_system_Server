# 配置文件
import os
import sys

Server_Ip = [
    '192.168.43.30',  # 手机wlan
    '192.168.137.240',  # tangjian Wlan
]
Server_Port = [
    9999, 9999, 12345, 7890, 12813, 10086
]

Client_Ip = [
    '192.168.43.30',
]
Client_Port = [
    34812, 24374,
]

Operat_server_IP = [
    '192.168.43.30',
]

Operat_server_Port = [
    47881,
]

BASE_DIR = os.path.abspath(os.path.join(os.getcwd(), "../.."))  # 项目根目录
SERVER_DIR = os.path.abspath(os.path.join(os.getcwd(), ".."))  # 上级目录
# print(SERVER_DIR)
ABSOLUTE_DIR = os.path.abspath(os.path.dirname(__file__))  # 当前目录

mycertfile_path = os.path.join(SERVER_DIR, 'server_ssl\mycertfile.pem')
mykeyfile_path = os.path.join(SERVER_DIR, 'server_ssl\mykeyfile.pem')
# print(mycertfile_path)

SECRET_KEY = 'tangjian_liubin'
