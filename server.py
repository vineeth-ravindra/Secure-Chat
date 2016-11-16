import os
import sys
import json
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class server():
    def __init__(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error, msg:
            print "Failed to create socket"
            sys.exit(0)
        try:
            self.sock.bind(('', 2424))
        except socket.error , msg:
            print "Failed to bind to socket "
            print msg
            sys.exit(0)

    def closeSocket(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
    
    def _parseData(self,data,address):
        try:
            data = json.loads(data)
            if data["messageType"] == "now-online" :
                self.sock.sendto("Wait! game is now going to start",address)
        except Exception as e:
            print "Unsolicited message from address :"+ str(address)
            return

    def run(self):
        print "Server running"
        while True:
            data , address = self.sock.recvfrom(2048);
            self._parseData(data,address);

if __name__ == "__main__":
    s = server()
    s.run()