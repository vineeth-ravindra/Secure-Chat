import socket
import pickle
import hashlib
import DH
import sys
import zlib
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

class connection:
    def __init__(self):
        self.diffi = DH.DiffieHellman()
        self.pubKey = self.diffi.gen_public_key()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except e:
            print "Error while creating socket"
            sys.exit(0)

        with open("public_key.pem", "rb") as key_file:
            try:
                self.serverPublicKey = serialization.load_pem_public_key(
                    key_file.read(),
                    backend = default_backend())
            except:
                print "Error while loading key " + file
                sys.exit(0)
    
    def sendData(self,obj):
        try:
            self.sock.sendto(obj,('',2424))
        except Exception as e:
            print "Error while sending data"

    def recvData(self):
        data = None
        while data is None:
            data = self.sock.recv(4096)
        data = pickle.loads(data)
        return data

    def encryptMessageWithServerPubKey(self, message):
        try:
            message = zlib.compress(message)
            cipherText = self.serverPublicKey.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
        except Exception as e:
            print "Unable to perform asymetric encryption",e
            sys.exit(0)
        return cipherText


    def sayHello(self):
        desObj = {"messageType":"now-online","user":"alice"} #TODO: Need to make sure the user is not hard coded
        desObj = pickle.dumps(desObj)
        self.sendData(desObj)

    def puzzleSolve(self,data):
        response = data["challange"]
        obj = {}
        for x in range (-1,65537):
            sha = hashlib.sha256()
            sha.update(response+str(x))
            if sha.digest() == data["answer"]:
               obj["answer"] = x
               obj["pubKey"] = self.pubKey
               obj = pickle.dumps(obj)
               obj = self.encryptMessageWithServerPubKey(obj)
               return pickle.dumps({
                   "encoded":obj,
                   "messageType":"quiz-response"
               })
        return False
            
    def establishConnection(self):
        # Step 1 : Say Hello 
        self.sayHello()
        data = self.recvData()
        #Step 2 : Send Response to challange
        data = self.puzzleSolve(data)
        self.sendData(data)



