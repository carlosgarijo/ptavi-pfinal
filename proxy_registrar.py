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

    def registrar_users(self, users_info):
        self.users_dicc = users_info


    def registered2file(self, sip_user):
        fich = open(DATABASE_PATH, "w")
        line = "User\tIP\tPort\tRegister time\tExpires\r\n"
        for user in self.users_dicc.keys():
            if user == sip_user:
                line += user + "\t" + self.users_dicc[user][0] + "\t"
                line += str(self.users_dicc[user][1]) + "\t"
                line += str(self.users_dicc[user][2]) + "\t"
                line += str(self.users_dicc[user][3]) + "\r\n"
        fich.write(line)


    def handle(self):
        # Escribe dirección y puerto del cliente (de tupla client_address)
        Client_IP = str(self.client_address[0])
        nonce = 1705201402032012
        self.registrar_users(users_info)
        while 1:
            # Leyendo línea a línea lo que nos envía el cliente
            line = self.rfile.read()
            line_decode = line.decode('utf-8')
            if line_decode:
                request = line_decode.split(" ")
                sip_user = request[1].split(':')[1]
                Client_Port = int(request[1].split(':')[-1])
                print("El cliente nos manda -- \r\n" + line_decode)
                Metodo_rcv = line_decode.split(" ")[0]
                if Metodo_rcv == "REGISTER":
                    if len(request) == 4:
                        expires = int(request[-1].split(':')[-1])
                        print(expires)
                        if expires > 0:
                            Answer = "SIP/2.0 401 Unauthorized\r\n"
                            Answer += "WWW Authenticate: nonce="
                            Answer += str(nonce) + "\r\n\r\n"
                            self.wfile.write(bytes(Answer, 'utf-8'))
                        elif expires == 0:
                            del self.users_dicc[sip_user]
                            Answer = "SIP/2.0 200 OK\r\n\r\n"
                            # FALTA AGREGAR SDP
                            self.wfile.write(bytes(Answer, 'utf-8'))
                    else:
                        expires = int(request[3].split('\r\n')[0])
                        if expires > 0:
                            response = request[-1].split('=')[-1]
                            response = response.split('\r')[0]
                            m = hashlib.md5()
                            for user in self.users_dicc.keys():
                                if user == sip_user:
                                    password = self.users_dicc[user]

                            m.update(bytes(password, 'utf-8'))
                            m.update(bytes(str(nonce), 'utf-8'))
                            if m.hexdigest() == response:
                                Answer = "SIP/2.0 200 OK\r\n\r\n"
                                # FALTA AGREGAR SDP
                                self.wfile.write(bytes(Answer, 'utf-8'))
                                self.users_dicc[sip_user] = (self.client_address[0], Client_Port,
                                                             time.time(), float(expires))
                            else:
                                Answer = "SIP/2.0 401 Unauthorized\r\n"
                                Answer += "WWW Authenticate: nonce="
                                Answer += str(nonce) + "\r\n\r\n"
                                self.wfile.write(bytes(Answer, 'utf-8'))
                        elif expires == 0:
                            del self.users_dicc[sip_user]
                            Answer = "SIP/2.0 200 OK\r\n\r\n"
                            # FALTA AGREGAR SDP
                            self.wfile.write(bytes(Answer, 'utf-8'))

                        self.registered2file(sip_user)

                elif Metodo_rcv == "INVITE":
                    Answer = "SIP/2.0 100 Trying\r\n\r\n"
                    Answer += "SIP/2.0 180 Ring\r\n\r\n"
                    Answer += "SIP/2.0 200 OK\r\n\r\n"
                    self.wfile.write(bytes(Answer, 'utf-8'))
                elif Metodo_rcv == "ACK":
                    """
                    aEjecutar = "./mp32rtp -i " + Client_IP
                    aEjecutar += " -p 23032 < " + fichero_audio
                    print("Ejecutamos... ", aEjecutar)
                    os.system(aEjecutar)
                    """
                elif Metodo_rcv == "BYE":
                    Answer = "SIP/2.0 200 OK\r\n\r\n"
                    self.wfile.write(bytes(Answer, 'utf-8'))
                    print("Terminando conversación... ")
                elif Metodo_rcv != ("REGISTER", "INVITE", "ACK", "BYE"):
                    Answer = "SIP/2.0 405 Method Not Allowed\r\n\r\n"
                    self.wfile.write(bytes(Answer, 'utf-8'))
                else:
                    Answer = "SIP/2.0 400 Bad Request\r\n\r\n"
                    self.wfile.write(bytes(Answer, 'utf-8'))
            # Si no hay más líneas salimos del bucle infinito
            if not line:
                break

if __name__ == "__main__":
    try:
        (_,Fich_Config) = sys.argv
    except:
        sys,exit("Usage: python3 proxy_registrar.py config")

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
        serv = socketserver.UDPServer(("", PR_PORT), SIPProxyHandler)
        print("Server " + NAME + " listening at port " + str(PR_PORT))
        serv.serve_forever()
    except KeyboardInterrupt:
        sys.exit("Apagando Proxy...")
