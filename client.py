import socket
import json
import subprocess
import argparse
import os

import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import MD5

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

def SendMSG(host, port, msg, password):
# Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    MSGPrefix = "startmsg"
    encrypted_msg = Encrypt(MSGPrefix+msg, password)
    # Connect to server and send data
    sock.connect((host, port))
    sock.sendall(encrypted_msg)

    # Receive data from the server and shut down
    received = str(sock.recv(1024))
    sock.close()
    reply = Decrypt(received, password) 
    if reply[:len(MSGPrefix)] != MSGPrefix:
        raise Exception( "error: msg from server doesn't start with msg prefix. The password is maybe wrong" )
    reply = reply[len(MSGPrefix):]

    if reply.startswith('error'):
        raise Exception( 'error from server: %s' % reply )

    return reply

def convert_disksize(size):
    nsize = float(size[0:-1])
    unit = size[-1]
    if unit == 'G':
        return nsize
    if unit == 'M':
        if nsize > 100:
            return nsize/1000.0
        else:
            return 0
    if unit == 'T':
        return nsize*1000.0
    if unit == 'K':
        return 0
    return size


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simplified tools')
    parser.add_argument( '--server', dest='server', 
            help='address of server', required=True )
    args = parser.parse_args()



    proc = subprocess.Popen("cat /proc/meminfo | grep MemTotal | awk '{print $2}'", stdout=subprocess.PIPE,shell=True)
    memory = int(proc.communicate()[0])/1e6
    proc = subprocess.Popen("cat /proc/cpuinfo | grep -c processor", stdout=subprocess.PIPE,shell=True)
    n_cores = int(proc.communicate()[0])
    proc = subprocess.Popen("cat /proc/cpuinfo | grep -m 1 'model name' | awk -F ': ' '{print $2}'", stdout=subprocess.PIPE,shell=True)
    cpu = proc.communicate()[0].strip()
    cpu_max_freq = 0
    if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"):
        proc = subprocess.Popen("cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", stdout=subprocess.PIPE,shell=True)
        cpu_max_freq = int(proc.communicate()[0])/1e6
    else:
        print "warning: max cpu freq not available. using 0 as max freq."
    proc = subprocess.Popen("hostname", stdout=subprocess.PIPE,shell=True)
    hostname = proc.communicate()[0].strip().split('.')[0]
    disk_size = 0.0
    disk_avail = 0.0
    if os.path.exists("/scratch/work"):
        proc = subprocess.Popen("df -h /scratch/work | tail -1 | awk '{print $2}'", stdout=subprocess.PIPE,shell=True)
        disk_size = convert_disksize(proc.communicate()[0].strip())
        proc = subprocess.Popen("df -h /scratch/work | tail -1 | awk '{print $4}'", stdout=subprocess.PIPE,shell=True)
        disk_avail = convert_disksize(proc.communicate()[0].strip())
    else:
        print "warning: /scratch/work does not exist. using 0 for disk size"

    jsondata = {}
    jsondata["hostname"] = hostname
    jsondata["memory"] = float( "%.1f" % memory )
    jsondata["n_cores"] = n_cores
    jsondata["cpu_max_freq"] = float( "%.1f" % cpu_max_freq )
    jsondata["cpu"] = cpu
    jsondata["disk_size"] = disk_size
    jsondata["disk_avail"] = disk_avail

    msg = json.dumps(jsondata)

    print SendMSG(args.server, 24242, msg, 'password123')
