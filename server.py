# Copyright 2018 Igor Santarek

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# SERVER APP

import socket
from threading import Thread
import os

class Host():
	socket = None
	ip = None

	def __init__(self, socket, ip):
		self.socket = socket
		self.ip = ip

is_on = True
hosts_count = 0
kill_all_connections = False
hosts_list = []
KEY = 120

def xor_crypt(data, key):
	encrypted = []
	for ch in data:
		encrypted.append(ch ^ key)
	return bytes(encrypted)

def has_host(ip):
	global hosts_list
	for host in hosts_list:
		if host.ip[0] == ip[0] and host.ip[1] == ip[1]:
			return True
	return False

def add_host(socket, ip):
	global hosts_list

	if not has_host(ip):
		hosts_list.append(Host(socket, ip))
		return True
	else:
		socket.close()
		return False

def remove_first_host(ip):
	global hosts_list
	i = 0
	while i < len(hosts_list):
		if hosts_list[i].ip[0] == ip[0] and hosts_list[i].ip[1] == ip[1]:
			del hosts_list[i]
		i += 1

def all_hosts_send(msg, not_send_ip):
	global hosts_list
	global KEY

	for host in hosts_list:
		if host.ip != not_send_ip:
			host.socket.send(xor_crypt(bytes(msg, 'utf8'), KEY))

def is_cmd(strr):
	return strr[0:3] == 'CMD' and (' ' in strr) and len(strr) >= 5

def get_cmd(strr):
	return strr.split(' ')[1]

def get_cmd_pars(strr):
	return strr.split(' ')[2:]

def send_encrypted(client_socket, msg):
	global KEY
	client_socket.send(xor_crypt(msg, KEY))

def connection(client_socket, ip):
	global KEY
	global kill_all_connections
	global hosts_count
	global REPO_NAME

	kill_connection = False
	while not kill_connection and not kill_all_connections:
		msg = str(xor_crypt(client_socket.recv(1024), KEY), 'utf8')
		if len(msg) > 0:
			if is_cmd(msg):
				cmd_name = get_cmd(msg)
				cmd_pars = get_cmd_pars(msg)
				if len(cmd_pars) > 0:
					print("Host with ip <"+ip[0]+":"+str(ip[1])+"> sent COMMAND: ", cmd_name, "with parameters: ", ' '.join(cmd_pars))
				else:
					print("Host with ip <"+ip[0]+":"+str(ip[1])+"> sent COMMAND: ", cmd_name)

				if cmd_name == 'KILL':
					kill_connection = True
				elif cmd_name == 'INFO':
					send_encrypted(client_socket, bytes("HOSTS COUNT: "+str(hosts_count), 'utf8'))
			else:
				all_hosts_send(msg, ip)
				print("Host with ip <"+ip[0]+":"+str(ip[1])+"> sent MESSAGE: ", msg)
	remove_first_host(ip)
	client_socket.close()
	hosts_count -= 1

def make_connection(client_socket, ip):
	global hosts_count

	if add_host(client_socket, ip):
		thread = Thread(target=connection, args = (client_socket, ip))
		thread.daemon = True
		thread.start()
		hosts_count += 1

def accept_connections_thread(server_sock):
	global is_on
	global kill_all_connections

	while is_on and not kill_all_connections:
		(client_socket, s_ip) = server_sock.accept()
		make_connection(client_socket, s_ip)

def main():
	global is_on
	global kill_all_connections

	print("SIMPLE TCP CHAT by Igor Santarek (SERVER)")
	print("SERVER IP: ")
	ip = input()
	if ip == '':
		ip = '127.0.0.1'
	port = 81
	try:
		server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_sock.bind((ip, port))
		server_sock.listen(30)
	except:
		print("Something went wrong!")
		return
	print("Server created correctly!")

	conn_thread = Thread(target = accept_connections_thread, args = (server_sock,))
	conn_thread.daemon = True
	conn_thread.start()

	while is_on and not kill_all_connections:
		cmd = input()
		if cmd == "/exit":
			kill_all_connections = True
			is_on = False
			break

if __name__ == "__main__":
	main()