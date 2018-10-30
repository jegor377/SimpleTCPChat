# Copyright 2018 Igor Santarek

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# CLIENT APP

import socket
from threading import Thread
import os

MAX_MSG_SIZE = 1024
is_on = True
KEY = 120

def xor_crypt(data, key):
	encrypted = []
	for ch in data:
		encrypted.append(ch ^ key)
	return bytes(encrypted)

def recv_thread(client_sock):
	global is_on
	global server_response

	while is_on:
		try:
			msg = str(xor_crypt(client_sock.recv(MAX_MSG_SIZE), KEY), 'utf8')
			if len(msg) > 0:
				print(msg)
		except:
			pass

def is_cmd(strr):
	return strr[0] == '/'

def send_cmd(client_sock, cmd, pars=()):
	global KEY
	if len(pars) > 0:
		client_sock.send(xor_crypt(bytes('CMD '+cmd+(' '.join(pars)), 'utf8'), KEY))
	else:
		client_sock.send(xor_crypt(bytes('CMD '+cmd, 'utf8'), KEY))

def upload_thread(client_sock, file_path, file_size):
	global KEY

	try:
		print("Uploading file \""+file_path+"\" with size "+str(file_size)+"...")
		with open(file_path, 'rb') as file:
			while True:
				piece = file.read(1024)

				if len(piece) <= 0:
					break

				print(str(piece, 'utf8'))
				client_sock.send(xor_crypt(piece, KEY))
		print("File uploaded!")
	except:
		print("Something went wrong!")

def upload_command(client_sock, file_path):
	if os.path.exists(file_path):
		file_size = os.path.getsize(file_path)
		MAX_FILE_SIZE = 1024 * 1024 * 1024 * 100 # 100MB
		if file_size <= MAX_FILE_SIZE:
			ut = Thread(target=upload_thread, args=(client_sock, file_path, file_size))
			ut.daemon = True
			ut.start()
	else:
		print("File doesn't exist!")

def main():
	global is_on

	print("SIMPLE TCP CHAT by Igor Santarek (CLIENT)")
	print("SERVER IP: ")
	ip = input()
	if ip == '':
		ip = '127.0.0.1'
	port = 81
	try:
		client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_sock.connect((ip, port))
		recv_t = Thread(target=recv_thread, args = (client_sock,) )
		recv_t.daemon = True
		recv_t.start()
	except:
		print("Something went wrong!")
		return
	print("Client connected correctly!")
	while is_on:
		msg = input()

		try:
			if is_cmd(msg):
				if msg == '/help':
					print('/exit - kills the program and connection.')
					print('/info - prints hosts count.')
					print('/upload <file path> - reads the text file and sends it to the server.')

				if msg == '/exit':
					is_on = False
					send_cmd(client_sock, 'KILL')
					client_sock.close()
				elif msg == '/info':
					send_cmd(client_sock, 'INFO')
				elif msg.split(' ')[0] == '/upload':
					file_path = ' '.join(msg.split(' ')[1:])
					upload_command(client_sock, file_path)
			else:
				if len(msg) <= MAX_MSG_SIZE and is_on:
					client_sock.send(xor_crypt(bytes(msg, 'utf8'), KEY))
		except:
			print("Connection interrupted!")
			is_on = False
			break

if __name__ == "__main__":
	main()