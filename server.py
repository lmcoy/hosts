import os
import math
import shutil
import time
import datetime
import logging
import socket
import random
import SocketServer
import pickle
import json
import traceback
import datetime


import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import MD5

logger = logging.getLogger("server")
ch = logging.StreamHandler()
frm = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%d.%m.%Y %H:%M:%S") 
ch.setFormatter(frm)
logger.addHandler(ch)

loglvl = logging.INFO
logger.setLevel(loglvl)
ch.setLevel(loglvl)


def _addPadding(data, interrupt, pad, block_size):
    if len(pad) != 1:
        raise Exception('pad must be only one character')
    if len(interrupt) != 1:
        raise Exception('interrupt must be only one character')
    new_data = ''.join( [data,interrupt])
    new_data_len = len(new_data)
    if new_data_len % block_size == 0:
        # no padding needed
        return new_data
    to_pad_len = block_size - new_data_len%block_size
    return ''.join([new_data, to_pad_len*pad])

def _stripPadding(data, interrupt, pad):
    return data.rstrip(pad).rstrip(interrupt)

def Encrypt(plaintext, password):
    h = MD5.new()
    h.update(password)
    secret_key = h.hexdigest()
    iv = Random.new().read( AES.block_size )
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    padded = _addPadding(plaintext, '\0', 'x', 32)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv+encrypted)

def Decrypt(encryptedtext, password):
    h = MD5.new()
    h.update(password)
    secret_key = h.hexdigest()
    decoded = base64.b64decode(encryptedtext)
    iv = decoded[:AES.block_size]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(decoded[AES.block_size:])
    return _stripPadding(decrypted, '\0', 'x')

class ServerException(Exception):
    def __init__(self, msg):
        self._msg = msg
    def __str__(self):
        return self._msg


class TCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        password = 'password123'
        plaintext = Decrypt(self.data, password)

        MSGPrefix = "startmsg"
        prefix = plaintext[:len(MSGPrefix)]
        if prefix != MSGPrefix:
            self.request.sendall( "error error error" )
            return

        jsondata = plaintext[len(MSGPrefix):]

        reply = ""
        try:
            mdata = json.loads(jsondata)
            reply = server.NewData(mdata)
        except Exception as e:
            traceback.print_stack()
            reply = "error: "+str(e)

        self.request.sendall(Encrypt(MSGPrefix+reply, password))


def days_since(date):
  d = datetime.datetime.strptime( date, '%Y-%m-%d')
  curtime = datetime.datetime.now()
  ret = (curtime-d).days
  return ret
  

class Server(SocketServer.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        SocketServer.TCPServer.__init__(self,server_address, RequestHandlerClass, bind_and_activate)


    def NewData(self, result):
        data = None
        
        with open('hosts.txt', 'r') as fin:
            data = json.load(fin)
            hostlist = data["aaData"]

            nlist = filter( lambda x: x["hostname"] != result["hostname"], hostlist )
            nlist = filter( lambda x: days_since(x["date"]) < 10, nlist )
            data["aaData"] = nlist

        result["date"] = datetime.datetime.now().strftime('%Y-%m-%d')
        data["aaData"].append(result)


        tmpfilename = "tmp.txt"
        with open(tmpfilename, "w") as tmpfile:
            json.dump(data,tmpfile)
        
        shutil.move(tmpfilename, 'hosts.txt')
        return "complete"



if __name__ == "__main__":
    HOST, PORT = socket.gethostname(), 24242
    server = Server( (HOST,PORT), TCPHandler)

    logger.info( "starting server on %s:%d" % (HOST,PORT) )
    server.serve_forever()
