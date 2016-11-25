import os
import pyDH
import pickle
import pymongo
import hashlib
from random import randint

class connection:
    def __init__(self):
        self.diffiObj = pyDH.DiffieHellman()
        
        
    def nowOnlineResponse(self):
        rand = os.urandom(100)
        t = randint(30000,65536)
        sha = hashlib.sha256()
        sha.update(rand+str(t))
        guess = sha.digest()
        obj = {"message-type":"quiz","challange":rand,"answer":guess}
        ret = pickle.dumps(obj)
        return ret

    def findPasswordHashForUser(self,user):
        with open("server.conf") as f:
            x = f.read()
            x = x.split('\n')
            for i in x:
                if i.split(":+++:")[0] == user:
                    return i.split(":+++:")[1]
        return False
            
    def challangeResponse(self,data):
        pubKey = self.diffiObj.gen_public_key()         #This is (gb mod p)
        senderPubKey = data["pubKey"]                   #This is (ga mod p)
        senderPassHash = self.findPasswordHashForUser(data["sender"])
        if senderPassHash:
            gpowaw = self.diffiObj.gen_shared_key(senderPassHash)
            sha = hashlib.sha256()
            sha.update(gpowaw)
            gpowaw = sha.digest()
            obj = {
                    "gpowaw":gpowaw,
                    "pubKey":pubKey
                }
            ret = pickle.dumps(obj)
            return ret
        return False

    def logErrors(self,errTime,address):
        print "There was an error during " + errTime + " from host"+address

    def _parseData(self,data,address):
        try:
            data = pickle.loads(data)
            if data["messageType"] == "now-online":
                ret = self.nowOnlineResponse()
                return ret
            if data["message-type"] == "quiz-response":
                ret = self.challangeResponse(data)
                if not ret:
                    self.logErrors("Response from sender",address)
                return ret
        except Exception as e:
            print "Unsolicited message from address :" + str(address)
            return False