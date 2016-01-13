#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Clase (y programa principal) para un servidor de eco en UDP simple
"""

import socket
import socketserver
import sys
import time
import os
import hashlib
import csv
from uaclient import Get_Time
from uaclient import Log
from xml.sax import make_parser
from xml.sax.handler import ContentHandler


class XMLHandler(ContentHandler):
    """
    Handler para leer la configuración en XMLHandler
    """

    def __init__(self):
        self.diccs = {'server': ['name', 'ip', 'puerto'],
                      'database': ['path', 'passwdpath'],
                      'log': ['path']}
        self.tag = []

    def startElement(self, name, attrs):
        if name in self.diccs:
            help_dicc = {}
            for atributo in self.diccs[name]:
                help_dicc[atributo] = attrs.get(atributo, "")
            self.tag.append([name, help_dicc])

    def get_tags(self):
        return self.tag


class SIPProxyHandler(socketserver.DatagramRequestHandler):
    """
    SIP Proxy server class
    """
    users_dicc = {}
    users_pwrd = {}

    def registrar_users(self, users_info):
        self.users_pwrd = users_info

    def registered2file(self):
        """
        Escribimos el fichero Database
        """
        fich = open(DATABASE_PATH, "w")
        #line = "User\tIP\tPort\tRegister time\tExpires\r\n"
        line = "Database:\n"
        for user in self.users_dicc.keys():
            line += user + "\t" + self.users_dicc[user][0] + "\t"
            line += str(self.users_dicc[user][1]) + "\t"
            line += str(self.users_dicc[user][2]) + "\t"
            line += str(self.users_dicc[user][3]) + "\r\n"
        fich.write(line)

    def expire_user(self):
        """
        Comprobamos si algun usuario ha expirado
        """
        for user in self.users_dicc.keys():
            total_time = self.users_dicc[user][2]
            total_time += self.users_dicc[user][3]
            if float(total_time) < time.time():
                del self.users_dicc[user]

    def reenvio(self, UAS_IP, UAS_PORT, line, Client_IP, C_Port):
        my_socket = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM)
        my_socket.setsockopt(socket.SOL_SOCKET,
                             socket.SO_REUSEADDR, 1)
        my_socket.connect((UAS_IP, UAS_PORT))
        LogText = line.decode('utf-8')
        Text_List = LogText.split('\r\n')
        LogText = " ".join(Text_List)
        Log(LOG_FICH, 'Send', LogText, UAS_IP, UAS_PORT)
        try:
            # Reenviamos al UAServer el INVITE
            my_socket.send(line)
            # Reenviamos al UAClient que realiza el INVITE
            data = my_socket.recv(1024)
            LogText = data.decode('utf-8')
            Text_List = LogText.split('\r\n')
            LogText = " ".join(Text_List)
            Log(LOG_FICH, 'Receive', LogText, UAS_IP, UAS_PORT)
            self.wfile.write(data)
            Log(LOG_FICH, 'Send', LogText, Client_IP, C_Port)
        except socket.error:
            Error = "Error: No User Agent Server Listening"
            print(Error)
            self.wfile.write(bytes(Error, 'utf-8'))
        my_socket.close()

    def handle(self):
        # Escribe dirección y puerto del cliente (de tupla client_address)
        Client_IP = str(self.client_address[0])
        C_Port = int(self.client_address[1])
        nonce = 1705201402032012
        self.registrar_users(users_info)
        while 1:
            # Comprobamos si algun usuario ha expirado
            self.expire_user()
            # Leyendo línea a línea lo que nos envía el cliente
            line = self.rfile.read()
            line_decode = line.decode('utf-8')
            if line_decode:
                request = line_decode.split(" ")
                print("El cliente nos manda -- \r\n" + line_decode)
                Metodo_rcv = line_decode.split(" ")[0]
                if Metodo_rcv == "REGISTER":
                    if len(request) == 4:
                        sip_user = request[1].split(':')[1]
                        expires = int(request[-1].split(':')[-1])
                        Client_Port = int(request[1].split(':')[-1])
                        LogText = line_decode
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Receive', LogText,
                            Client_IP, Client_Port)
                        # Miramos el Expires
                        if expires > 0:
                            Answer = "SIP/2.0 401 Unauthorized\r\n"
                            Answer += "WWW Authenticate: nonce="
                            Answer += str(nonce) + "\r\n\r\n"
                            self.wfile.write(bytes(Answer, 'utf-8'))
                        elif expires == 0:
                            # Borramos
                            del self.users_dicc[sip_user]
                            Answer = "SIP/2.0 200 OK\r\n\r\n"
                            self.wfile.write(bytes(Answer, 'utf-8'))
                        LogText = Answer
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Send', LogText, Client_IP, Client_Port)

                    else:
                        # Comprobamos el response del cliente con el
                        # del proxy_registrar
                        C_Port_Rsp = int(request[1].split(':')[-1])
                        sip_user = request[1].split(':')[1]
                        expires = int(request[3].split('\r\n')[0])
                        expires = float(expires)
                        LogText = line_decode
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Receive', LogText,
                            Client_IP, C_Port_Rsp)
                        response = request[-1].split('=')[-1]
                        response = response.split('\r')[0]
                        m = hashlib.md5()
                        for user in self.users_pwrd.keys():
                            if user == sip_user:
                                password = self.users_pwrd[user]

                        m.update(bytes(password, 'utf-8'))
                        m.update(bytes(str(nonce), 'utf-8'))
                        if m.hexdigest() == response:
                            Answer = "SIP/2.0 200 OK\r\n\r\n"
                            self.wfile.write(bytes(Answer, 'utf-8'))
                            self.users_dicc[sip_user] = (Client_IP, C_Port_Rsp,
                                                         time.time(), expires)
                        else:
                            Answer = "SIP/2.0 401 Unauthorized\r\n"
                            Answer += "WWW Authenticate: nonce="
                            Answer += str(nonce) + "\r\n\r\n"
                            self.wfile.write(bytes(Answer, 'utf-8'))

                        LogText = Answer
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Send', LogText, Client_IP, C_Port_Rsp)
                    # Registramos al usuario
                    self.registered2file()

                elif Metodo_rcv == "INVITE":
                    invited_user = request[1].split(':')[-1]
                    if invited_user in self.users_dicc:
                        UAS_IP = self.users_dicc[invited_user][0]
                        UAS_PORT = self.users_dicc[invited_user][1]
                        UAS_PORT = int(UAS_PORT)
                        print('Reenviamos a...' + UAS_IP +
                              ' - ' + str(UAS_PORT))
                        self.reenvio(UAS_IP, UAS_PORT, line, Client_IP, C_Port)
                    else:
                        Answer = "SIP/2.0 404 User Not Found\r\n"
                        self.wfile.write(bytes(Answer, 'utf-8') + b'\r\n')
                        LogText = Answer
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Send', LogText, Client_IP, C_Port)

                elif Metodo_rcv == "ACK":
                    invited_user = request[1].split(':')[-1]
                    UAS_IP = self.users_dicc[invited_user][0]
                    UAS_PORT = self.users_dicc[invited_user][1]
                    UAS_PORT = int(UAS_PORT)
                    print('Reenviamos a...' + UAS_IP + ' - ' + str(UAS_PORT))
                    self.reenvio(UAS_IP, UAS_PORT, line, Client_IP, C_Port)
                elif Metodo_rcv == "BYE":
                    invited_user = request[1].split(':')[-1]
                    if invited_user in self.users_dicc:
                        UAS_IP = self.users_dicc[invited_user][0]
                        UAS_PORT = self.users_dicc[invited_user][1]
                        UAS_PORT = int(UAS_PORT)
                        print('Reenviamos a...' + UAS_IP +
                              ' - ' + str(UAS_PORT))
                        self.reenvio(UAS_IP, UAS_PORT, line, Client_IP, C_Port)
                    else:
                        Answer = "SIP/2.0 404 User Not Found\r\n"
                        self.wfile.write(bytes(Answer, 'utf-8') + b'\r\n')
                        LogText = Answer
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Send', LogText, Client_IP, C_Port)
                elif Metodo_rcv != ("REGISTER", "INVITE", "ACK", "BYE"):
                    Answer = "SIP/2.0 405 Method Not Allowed\r\n"
                    self.wfile.write(bytes(Answer, 'utf-8') + b'\r\n')
                    LogText = Answer
                    Text_List = LogText.split('\r\n')
                    LogText = " ".join(Text_List)
                    Log(LOG_FICH, 'Send', LogText, Client_IP, C_Port)
                else:
                    Answer = "SIP/2.0 400 Bad Request\r\n"
                    self.wfile.write(bytes(Answer, 'utf-8') + b'\r\n')
                    LogText = Answer
                    Text_List = LogText.split('\r\n')
                    LogText = " ".join(Text_List)
                    Log(LOG_FICH, 'Send', LogText, Client_IP, C_Port)
            # Si no hay más líneas salimos del bucle infinito
            if not line:
                break

if __name__ == "__main__":
    try:
        (_, Fich_Config) = sys.argv
    except:
        sys.exit("Usage: python3 proxy_registrar.py config")

    parser = make_parser()
    Handler = XMLHandler()
    parser.setContentHandler(Handler)
    parser.parse(open(Fich_Config))
    Dicc = Handler.get_tags()
    NAME = Dicc[0][1]['name']
    PR_PORT = Dicc[0][1]['puerto']
    PR_PORT = int(PR_PORT)
    PR_IP = Dicc[0][1]['ip']
    if not PR_IP:
        PR_IP = '127.0.0.1'
    PSSWRD_PATH = Dicc[1][1]['passwdpath']
    DATABASE_PATH = Dicc[1][1]['path']
    LOG_FICH = Dicc[2][1]['path']

    # Cogemos las contraseñas del fichero passwords.txt
    with open(PSSWRD_PATH, newline='') as pwrd_fich:
        lineas = csv.reader(pwrd_fich)
        users_info = {}
        for linea in lineas:
            help_line = linea[0].split(':')
            users_info[help_line[0]] = help_line[-1]

    try:
        Log(LOG_FICH, 'Start', '', PR_IP, PR_PORT)
        serv = socketserver.UDPServer(("", PR_PORT), SIPProxyHandler)
        print("Server " + NAME + " listening at port " + str(PR_PORT))
        serv.serve_forever()
    except KeyboardInterrupt:
        Log(LOG_FICH, 'Finish', '', PR_IP, PR_PORT)
        sys.exit("Apagando Proxy...")
