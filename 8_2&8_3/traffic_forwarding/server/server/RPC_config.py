import json
import asyncio
# from config.config import Operat_server_IP, Operat_server_Port
from xmlrpc.client import ServerProxy


server = ServerProxy("http://localhost:12039")  # 初始化服务器

while True:
    print('(1)/(find -all):获取所有在线客户端\n(2)/(break -all):关闭所有客户端连接\n(3)/(config):配置客户端')
    cmd = input('输入执行命令：')
    if cmd == '1' or cmd == 'find -all':
        user_list_json = server.get_all_client()
        user_list = json.loads(user_list_json)
        # print(user_list)
        user_info = []
        for user_ip in user_list:
            user_info.append(user_list[user_ip]['addr'])
        print(user_info)
    elif cmd == '2' or cmd == 'break -all':
        break_all_result = server.break_all_client()
        print(break_all_result)
    elif cmd == '3' or cmd == 'config':
        # 调用rpc服务端配置客户端
        user_list_json2 = server.get_all_client()
        user_list2 = json.loads(user_list_json2)
        user_wait_info = {}
        for user_ip in user_list2:
            if user_list2[user_ip]['have_config'] is None:
                user_wait_info[user_ip]=user_list2[user_ip]
        if user_wait_info is None:
            pass
        print('尚未配置的客户端：\n'+str(user_wait_info))
        choose_user = input("请输入你要配置的客户端ip(取消：exit)：")
        if choose_user == 'exit':
            continue
        # src_ip = input("请输入src_ip:")
        # src_port = input("请输入src_port:")
        # dst_ip = input("请输入dst_ip:")
        # dst_port = input("请输入dst_port:")
        src_ip = '127.0.0.1'
        src_port = 22
        # dst_ip = '192.168.43.218'
        dst_ip = '192.168.43.30'
        # dst_port = 10022
        dst_port = 11111
        rule = {'user_ip':choose_user,'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port}
        config_result = server.config_user(rule)
        if config_result:
            print("用户"+choose_user+'规则配置成功')
        else:
            print("用户"+choose_user+'规则配置失败！！！')
