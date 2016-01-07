#!/usr/bin/python3
# -*- coding: utf-8 -*-

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import sys
import socketserver
import time
import os
from uaclient import Get_Time
from uaclient import Log
from uaclient import SmallSMILHandler


class SIPServerHandler(socketserver.DatagramRequestHandler):
    """
    SIP server class
    """
    RTP_info = {'ip': '', 'port': 0}

    def handle(self):
        # Escribe dirección y puerto del cliente (de tupla client_address)
        Client_IP = str(self.client_address[0])
        fichero_audio = SONG
        Method_List = ['INVITE', 'ACK', 'BYE']
        while 1:
            # Leyendo línea a línea lo que nos envía el cliente
            line = self.rfile.read()
            line_decode = line.decode('utf-8')
            if line_decode:
                request = line_decode.split(" ")
                print("El cliente nos manda -- \r\n" + line_decode)
                LogText = line_decode
                Text_List = LogText.split('\r\n')
                LogText = " ".join(Text_List)
                Log(LOG_FICH, 'Receive', LogText,
                    Client_IP, int(self.client_address[1]))
                Metodo_rcv = request[0]
                if Metodo_rcv in Method_List:
                    if Metodo_rcv == "INVITE":
                        RTP_IP_Send = request[4].split("\r\n")[0]
                        RTP_PORT_Send = int(request[6])
                        self.RTP_info['ip'] = RTP_IP_Send
                        self.RTP_info['port'] = RTP_PORT_Send
                        # Creamos respuesta
                        Answer = "SIP/2.0 100 Trying\r\n\r\n"
                        Answer += "SIP/2.0 180 Ring\r\n\r\n"
                        Answer += "SIP/2.0 200 OK\r\n"
                        SDP = 'v=0\r\no=' + NAME + ' ' + UAS_IP
                        SDP += '\r\ns=Avengers Sesion\r\nt=0\r\nm=audio '
                        SDP += str(RTP_PORT) + ' RTP\r\n\r\n'
                        Answer += 'Content-Type: application/sdp'
                        Answer += '\r\n\r\n' + SDP
                        self.wfile.write(bytes(Answer, 'utf-8'))
                        LogText = Answer
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Send', LogText,
                            Client_IP, int(self.client_address[1]))
                    elif Metodo_rcv == "ACK":
                        # Enviamos audio
                        print("Enviamos audio a " + self.RTP_info['ip'] +
                              "-" + str(self.RTP_info['port']))
                        aEjecutar = "./mp32rtp -i " + self.RTP_info['ip']
                        aEjecutar += " -p " + str(self.RTP_info['port'])
                        aEjecutar += " < " + fichero_audio
                        print("Ejecutamos... ", aEjecutar)
                        os.system(aEjecutar)
                        print("Envio finalizado")
                    elif Metodo_rcv == "BYE":
                        # Enviamos respuesta
                        Answer = "SIP/2.0 200 OK\r\n"
                        self.wfile.write(bytes(Answer, 'utf-8') + b'\r\n')
                        LogText = Answer
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Send', LogText,
                            Client_IP, int(self.client_address[1]))
                        print("Terminando conversación... ")
                    elif Metodo_rcv != ("INVITE", "ACK", "BYE"):
                        Answer = "SIP/2.0 405 Method Not Allowed\r\n"
                        self.wfile.write(bytes(Answer, 'utf-8') + b'\r\n')
                        LogText = Answer
                        Text_List = LogText.split('\r\n')
                        LogText = " ".join(Text_List)
                        Log(LOG_FICH, 'Send', LogText,
                            Client_IP, int(self.client_address[1]))
                else:
                    Answer = "SIP/2.0 400 Bad Request\r\n"
                    self.wfile.write(bytes(Answer, 'utf-8') + b'\r\n')
                    LogText = Answer
                    Text_List = LogText.split('\r\n')
                    LogText = " ".join(Text_List)
                    Log(LOG_FICH, 'Send', LogText,
                        Client_IP, int(self.client_address[1]))
            # Si no hay más líneas salimos del bucle infinito
            if not line:
                break

if __name__ == "__main__":
    try:
        (_, Fich_Config) = sys.argv
    except:
        sys.exit("Usage: python3 uaserver.py config")

    parser = make_parser()
    Handler = SmallSMILHandler()
    parser.setContentHandler(Handler)
    parser.parse(open(Fich_Config))
    Dicc = Handler.get_tags()  # Diccionario con los atributos del fichero xml
    NAME = Dicc[0][1]['username']
    PSSWRD = Dicc[0][1]['passwd']
    UAS_IP = Dicc[1][1]['ip']
    if not UAS_IP:
        UAS_IP = '127.0.0.1'

    UAS_PORT = Dicc[1][1]['puerto']
    UAS_PORT = int(UAS_PORT)
    RTP_PORT = Dicc[2][1]['puerto']
    PR_IP = Dicc[3][1]['ip']
    PR_PORT = Dicc[3][1]['puerto']
    PR_PORT = int(PR_PORT)
    LOG_FICH = Dicc[4][1]['path']
    SONG = Dicc[5][1]['path']
    try:
        Log(LOG_FICH, 'Start', '', PR_IP, PR_PORT)
        serv = socketserver.UDPServer(("", UAS_PORT), SIPServerHandler)
        print("Listening...")
        serv.serve_forever()
    except KeyboardInterrupt:
        Log(LOG_FICH, 'Finish', '', PR_IP, PR_PORT)
        sys.exit("Apagando uaserver...")
