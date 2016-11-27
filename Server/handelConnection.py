import os,sys,DH,pickle,binascii
import hashlib,zlib,json
from random import randint
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class Connection:
    '''
        Provides adapter interfaces to Server Object
        Identifies the type of incoming  message and on the socket
         and generates appropriate response to send to client
         Provides augmented strong password authentication
    '''
    def __init__(self):
        '''
           __init__(None):
                Input  : None
                Output : None
                Purpose : 1) Initialise Connection object
                          2) Read server private key for future use
        '''
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
        '''
            __nowOnlineResponse(None):
                Input  : None
                Output : Obj { }
                Message format
                    {"message-type":"quiz", challange, hash{answer}}
                Purpose : When Client shows intent to connect Generate a challenge
                            and send it to server
        '''
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
        '''
            __challangeResponse(Object):
            Input  : Object {messageType:"quiz-response", encoded } (Response from server to challenge)
                            encoded -> {g^a mod p,response}s
            Output : Object {}
            Message format :
                        {messageType:"initiageSecret", sha256(g^ab mod p + g^bw mod p), g^b mod p}
            Purpose : Send server public secret and augmented information

        '''
        response = self.__decryptMessageUsingPrivateKey(data["encoded"])
        response = zlib.decompress(response)
        response = pickle.loads(response)
        pubKey = self.diffiObj.gen_public_key()                                     # This is (gb mod p)
        senderPubKey = long(response["pubKey"])                                     # This is (ga mod p)
        sharedSecret = self.diffiObj.gen_shared_key(senderPubKey)                   # This is (gab mop p)
        print sharedSecret
        userPassHash = self.__findPasswordHashForUser(data["user"])
        if userPassHash:
            gpowbw = self.diffiObj.gen_gpowxw(pubKey,userPassHash)
            sha = hashlib.sha256()
            sha.update(str(gpowbw)+str(sharedSecret))
            hash = int(binascii.hexlify(sha.digest()), base=16)
            obj = {
                    "messageType" : "initiateSecret",
                    "hash":hash,
                    "pubKey":pubKey,
                }
            ret = pickle.dumps(obj)
            return ret
        return False



    def __decryptMessageUsingPrivateKey(self, message):
        '''
            __decryptMessageUsingPrivateKey(String):
                    Input   : String
                    Output  : String
                    Purpose : Decrypt data encrypted with server public key

        '''
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
        '''
            __logErrors(String,tupple):
                Input   : String , Tupple(address)
                Output  : None
                Purpose : Log errors on console

        '''
        print "There was an error during " + errTime + " from host"+ str(address)

    def __gen384Hash(self,gpowbw,sharedSecret):
        '''
            __gen384Hash(float,float) :
                    Input   : g^bw mod p , g^ab mod p
                    Output  : sha384(g^bw mod p + g^ab mod p)
                    Purpose :
                                Data used to determine at the server if the client has
                                the right password

        '''
        sha = hashlib.sha384()
        sha.update(str(gpowbw) + str(sharedSecret))
        hash = int(binascii.hexlify(sha.digest()), base=16)
        return hash

    def __completeAuth(self,data):
        '''
            __completeAuth(Object) :
                Input  : Object
                Output :

        '''
        hash = data["hash"]
        print hash
        #TODO  : Verify if sha384 is same
        #TODO  : Store sesssion key and complete this whole process
        print "Hurray Hurry"
        return False

    def parseData(self,data,address):
        '''
            _parseData(String,tupple):
                Input   : String,tupple (Input from socket and incoming address)
                Output  : String (data to be sent to server
                Purpose : Parses the incoming message and  generate appropriate response
                            to send to client

        '''
        try:
            data = pickle.loads(data)
        except Exception as e:
            print "Unsolicited message from address :" + str(address)
            return False

        ret = False
        if data["messageType"] == "now-online":
            ret = self.__nowOnlineResponse()
        elif data["messageType"] == "quiz-response":
            ret = self.__challangeResponse(data)

        elif data["messageType"] == "complete":
            ret = self.__completeAuth(data)

        if not ret:
            self.__logErrors("Response from sender",address)
            return "unknownMessage"
        else :
            return ret
