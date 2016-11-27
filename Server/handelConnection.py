import os,sys,DH,pickle,binascii
import hashlib,zlib,pymongo,json
from random import randint
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class connection:
    def __init__(self):
        self.diffiObj = DH.DiffieHellman()
        with open("private_key.pem", "rb") as key_file:
            try:
                self.__privateKey = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
            except:
                print "Error while Loading key " + file
                sys.exit(0)
        
        
    def __nowOnlineResponse(self):
        rand = os.urandom(100)
        t = randint(30000,65536)
        sha = hashlib.sha256()
        sha.update(rand+str(t))
        guess = sha.digest()
        obj = {"message-type":"quiz","challange":rand,"answer":guess}
        ret = pickle.dumps(obj)
        return ret

    def __findPasswordHashForUser(self,user):
        with open("SERVER.conf") as json_file:
            json_data = json.load(json_file)
            if user.lower() in json_data:
                return json_data[user.lower()]
            else :
                return False
            
    def __challangeResponse(self,data):
        response = self.__decryptMessageUsingPrivateKey(data["encoded"])
        response = zlib.decompress(response)
        response = pickle.loads(response)
        pubKey = self.diffiObj.gen_public_key()                                     # This is (gb mod p)
        senderPubKey = long(response["pubKey"])                                     # This is (ga mod p)
        sharedSecret = self.diffiObj.gen_shared_key(senderPubKey)                   # This is (gab mop p)
        userPassHash = self.__findPasswordHashForUser(data["user"])
        if userPassHash:
            gpowbw = self.diffiObj.gen_gpowxw(pubKey,userPassHash)
            sha = hashlib.sha256()
            sha.update(str(gpowbw)+str(sharedSecret))
            hash = int(binascii.hexlify(sha.digest()), base=16)
            obj = {
                    "hash":hash,
                    "pubKey":pubKey,
                }
            ret = pickle.dumps(obj)
            return ret
        return False



    def __decryptMessageUsingPrivateKey(self, message):
        try:
            plainText = self.__privateKey.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
        except:
            print "Unable to perform symetric decryption"
            sys.exit(0)
        return plainText

    def __logErrors(self,errTime,address):
        print "There was an error during " + errTime + " from host"+address

    def _parseData(self,data,address):
        try:
            data = pickle.loads(data)
            if data["messageType"] == "now-online":
                ret = self.__nowOnlineResponse()
                return ret
            if data["messageType"] == "quiz-response":
                ret = self.__challangeResponse(data)
                if not ret:
                    self.__logErrors("Response from sender",address)
                return ret
        except Exception as e:
            print "Unsolicited message from address :" + str(address)
            return False