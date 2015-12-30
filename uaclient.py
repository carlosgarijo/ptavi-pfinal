#!/usr/bin/python3
# -*- coding: utf-8 -*-

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import sys
import socket
import time
import hashlib


def Get_Time():
    """
    Devuelve la hora actual en formato Año-Mes-Día-Horas-Minutos-Segundos
    """

    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time()))

def Log(fich, mode, text, Ip, Port):
    """
    Escribe en un fichero de log en modo APPEND
    """

    txt = open(fich, 'a')
    if mode == 'Start':
        txt.write(Get_Time() + " Starting...\r\n")
    elif mode == 'Finish':
        txt.write(Get_Time() + " Finishing.\r\n")
    elif mode == 'Send':
        txt.write(Get_Time() + ' Sent to ' + Ip + ':' + str(Port) + ': ' +
                  text + '\r\n')
    elif mode == 'Receive':
        txt.write(Get_Time() + ' Received from ' + Ip + ':' + str(Port) +
                  ': ' + text + '\r\n')
    elif mode == 'Error':
        txt.write(Get_Time() + ' ' + text + '\r\n')
    txt.close()

class SmallSMILHandler(ContentHandler):

    def __init__(self):
        self.diccs = {'account': ['username', 'passwd'],
                      'uaserver': ['ip', 'puerto'],
                      'rtpaudio': ['puerto'],
                      'regproxy': ['ip', 'puerto'],
                      'log': ['path'],
                      'audio': ['path']}

        self.tag = []

    def startElement(self, name, attrs):
        if name in self.diccs:
            help_dicc = {}
            for atributo in self.diccs[name]:
                help_dicc[atributo] = attrs.get(atributo, "")
            self.tag.append([name, help_dicc])

    def get_tags(self):
        return self.tag


if __name__ == "__main__":
# Cliente UDP simple.
    try:
        (_,Fich_Config, Metodo, Option) = sys.argv
        Metodo = Metodo.upper()
    except:
        sys.exit("Usage: python3 uaclient.py config method option")

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
    RTP_PORT = Dicc[2][1]['puerto']
    PR_IP = Dicc[3][1]['ip']
    PR_PORT = Dicc[3][1]['puerto']
    PR_PORT = int(PR_PORT)
    LOG_FICH = Dicc[4][1]['path']
    SONG = Dicc[5][1]['path']

    if Metodo == "REGISTER":
        request = Metodo + ' sip:' + NAME + ':' + UAS_PORT + ' SIP/2.0\r\n'
        request += 'Expires: ' + Option + '\r\n'
    elif Metodo == "INVITE":
        request = Metodo + ' sip:' + Option + ' SIP/2.0\r\n'
        description = 'v=0\r\no=' + NAME + ' ' + UAS_IP
        description += '\r\ns=Avengers Sesion\r\nt=0\r\nm=audio '
        description += str(RTP_PORT) + ' RTP\r\n'
        request += 'Content-Type: application/sdp' + '\r\n\r\n' + description
    elif Metodo == "BYE":
        request = Metodo + ' sip:' + Option + ' SIP/2.0\r\n\r\n'
    else:
        sys.exit('No valid METHOD')

    # Creamos el socket, lo configuramos y lo atamos a un servidor/puerto
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((PR_IP, PR_PORT))

    Log(LOG_FICH, 'Start', '', PR_IP, PR_PORT)
    print("Enviando: \r\n" + request)
    LogText = request
    Text_List = LogText.split('\r\n')
    LogText = " ".join(Text_List)
    Log(LOG_FICH, 'Send', LogText, PR_IP, PR_PORT)

    try:
        request_encoded = request.encode('utf-8')
        my_socket.send(request_encoded + b'\r\n')
        Answer = my_socket.recv(1024)
    except socket.error:
        LogText = 'Error: No server listening at ' + PR_IP + ' port ' + PR_PORT
        Log(LOG_FICH, 'Error', LogText, '', '')
        sys.exit(LogText)

    Answer_decode = Answer.decode('utf-8')
    print("Recibido: \r\n" + Answer_decode)
    LogText = Answer_decode
    Text_List = LogText.split('\r\n')
    LogText = " ".join(Text_List)
    Log(LOG_FICH, 'Receive', LogText, PR_IP, PR_PORT)
    Answer_list = Answer_decode.split("\r\n")
    print(Answer_list)
    Answer_list.pop()
    if Answer_list[0] == "SIP/2.0 401 Unauthorized":
        m = hashlib.md5()
        nonce = Answer_list[1].split("=")[-1]
        m.update(bytes(PSSWRD, 'utf-8'))
        m.update(bytes(nonce, 'utf-8'))
        request += "Authorization: response=" + m.hexdigest() + "\r\n"
        request_encoded = request.encode('utf-8')
        my_socket.send(request_encoded + b'\r\n')
        print("Enviando: \r\n" + request)
        LogText = request
        Text_List = LogText.split('\r\n')
        LogText = " ".join(Text_List)
        Log(LOG_FICH, 'Send', LogText, PR_IP, PR_PORT)
    elif Answer_list[0] == "SIP/2.0 100 Trying":
        Metodo = "ACK"
        line = Metodo + " sip:" + Option + " SIP/2.0\r\n\r\n"
        print("Enviando: \r\n" + line)
        my_socket.send(bytes(line, 'utf-8') + b'\r\n')
        LogText = line
        Text_List = LogText.split('\r\n')
        LogText = " ".join(Text_List)
        Log(LOG_FICH, 'Send', LogText, PR_IP, PR_PORT)
        # Envio de audio

    Answer = my_socket.recv(1024)
    Answer_decode = Answer.decode('utf-8')
    if Answer_decode:
        print("Recibido: \r\n" + Answer_decode)
        LogText = Answer_decode
        Text_List = LogText.split('\r\n')
        LogText = " ".join(Text_List)
        Log(LOG_FICH, 'Receive', LogText, PR_IP, PR_PORT)
    print("Terminando socket...")

    # Cerramos todo
    my_socket.close()
    Log(LOG_FICH, 'Finish', '', PR_IP, PR_PORT)
    print("Fin.")
