import socket
import pickle
import hashlib
import pyDH

class connection:
    def __init__(self):
        self.diffi = pyDH.DiffieHellman()
        self.pubKey = self.diffi.gen_public_key()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except e:
            print "Error while creating socket"
            sys.exit(0)
    
    def sendData(self,obj):
        obj = pickle.dumps(obj)
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

    def sayHello(self):
        desObj = {"messageType":"now-online"}
        self.sendData(desObj)

    def puzzleSolve(self,data):
        response = data["challange"]
        obj = {}
        for x in range (-1,65537):
            sha = hashlib.sha256()
            sha.update(response+str(x))
            if sha.digest() == data["answer"]:
               obj["response"] = x
               obj["pubKey"] = self.pubKey
               return obj
        return False
            
    def establishConnection(self):
        # Step 1 : Say Hello 
        self.sayHello()
        data = self.recvData()
        #Step 2 : Send Response to challange
        data = self.puzzleSolve(data)
        self.sendData(data)



