#!/usr/bin/python3
# -*- coding: utf-8 -*-

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import sys
import socketserver
import time
from uaclient import Get_Time
from uaclient import Log
from uaclient import SmallSMILHandler

if __name__ == "__main__":
# Cliente UDP simple.
    try:
        (_,Fich_Config) = sys.argv
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
RTP_PORT = Dicc[2][1]['puerto']
PR_IP = Dicc[3][1]['ip']
PR_PORT = Dicc[3][1]['puerto']
PR_PORT = int(PR_PORT)
LOG_FICH = Dicc[4][1]['path']
SONG = Dicc[5][1]['path']
