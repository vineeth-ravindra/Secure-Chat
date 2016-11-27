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
            
    def __challangeResponse(self,senderObj):
        '''
            __challangeResponse(Object):
            Input  : Object {messageType:"quiz-response", encoded } (Response from server to challenge)
                            encoded -> {g^a mod p,response}s
            Output : Object {}
            Message format :
                        {messageType:"initiageSecret", sha256(g^ab mod p + g^bw mod p), g^b mod p}
            Purpose : Send server public secret and augmented information

        '''

        pubKey = self.diffiObj.gen_public_key()                                               # This is (gb mod p)
        self.__sharedSecret = self.diffiObj.gen_shared_key(long(senderObj["pubKey"]))         # This is (gab mop p)
        print "Shared Secret is : ", self.__sharedSecret
        userPassHash = self.__findPasswordHashForUser(senderObj["user"])
        if userPassHash:
            gpowbw = self.diffiObj.gen_gpowxw(pubKey,userPassHash)
            sha = hashlib.sha256()
            sha.update(str(gpowbw)+str(self.__sharedSecret))
            hash = int(binascii.hexlify(sha.digest()), base=16)
            return pickle.dumps({
                    "messageType" : "initiateSecret",
                    "hash"        :hash,
                    "pubKey"      :pubKey,
                })
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
        except Exception as e:
            print "Unable to perform asymmetric decryption",e
            sys.exit(0)
        return zlib.decompress(plainText)

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
        #TODO  : Verify if sha384 is same
        #TODO  : Store sesssion key and complete this whole process
        print "Hurray Hurry"
        return False

    def __loadPickledData(self,message):
        try:
            return pickle.loads(message)
        except Exception as e:
            return False

    def __parseStreamData(self,message):
        '''
            __parseStreamData(String):
                Input   : String (Data on sock stream)
                Output  : Obj
                Purpose : Given the data sent by the client on the wire
                            the data is unpickled, decrypted and converted
                             into object for further use
        '''
        unPickledData = self.__loadPickledData(message)
        if unPickledData is False:
            self.__logErrors("Error while trying to dump data",('',''))
        decryptedResponse = self.__decryptMessageUsingPrivateKey(unPickledData["message"])
        decryptedResponse = self.__loadPickledData(decryptedResponse)
        decryptedResponse["user"] = unPickledData["user"]
        return decryptedResponse

    def parseData(self,data,address):
        '''
            _parseData(String,tupple):
                Input   : String,tupple (Input from socket and incoming address)
                Output  : String (data to be sent to server
                Purpose : Parses the incoming message and  generate appropriate response
                            to send to client

        '''
        decryptedResponse = self.__parseStreamData(data)
        ret = False
        if decryptedResponse["messageType"] == "now-online":
            ret = self.__nowOnlineResponse()
        elif decryptedResponse["messageType"] == "quiz-response":
            ret = self.__challangeResponse(decryptedResponse)
        elif decryptedResponse["messageType"] == "complete":
            ret = self.__completeAuth(decryptedResponse)
        if not ret:
            self.__logErrors("Response from sender",address)
            return "unknownMessage"
        else :
            return ret
