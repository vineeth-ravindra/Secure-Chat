import os,sys,DH,pickle,binascii
import hashlib,zlib,json
from Auth import Auth
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
        self.__diffiObj = DH.DiffieHellman()
        self.__authDict      = {}
        self.__sessionKeyDict = {}
        with open("private_key.pem", "rb") as key_file:
            try:
                self.__privateKey = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
            except:
                print "Error while Loading key " + file
                sys.exit(0)
        
        
    def __nowOnlineResponse(self,senderObj):
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
        self.__authDict[senderObj["user"]] = Auth(str(t))
        obj = {"message-type":"quiz","challange":rand,"answer":guess}
        ret = pickle.dumps(obj)
        return ret

    def __findPasswordHashForUser(self,user):
        '''
            __findPasswordHashForUser(String):
                Input   :   (String) UserName
                Output  :   False  -> If username not found
                            String -> Password hash
                Purpose :   Given a username searches if the user is registerd
                            and returns the username
        '''
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
            Output : String
            Message format :
                        {messageType:"initiageSecret", sha256(g^ab mod p + g^bw mod p), g^b mod p}
            Purpose : Send server public secret and augmented information

        '''

        if senderObj["user"] in self.__authDict:
            authInfo = self.__authDict[senderObj["user"]]
            print "Server side quizz",authInfo.getQuizz()
            print "Client Side", senderObj["answer"]
            if authInfo.getQuizz() == str(senderObj["answer"]):
                return self.__challangeResponseHelper(senderObj, authInfo)
            else :
                self.__authDict.pop(senderObj["user"])
        return False

    def __challangeResponseHelper(self,senderObj,authInfo):
        '''
            __challangeResponseHelper(Object,Object):
                    Input   : The  Objectified stream data from user
                                and Authentication info on server
                    Output : String (Data to be send on wire)
                     Message format :
                        {messageType:"initiageSecret", sha256(g^ab mod p + g^bw mod p), g^b mod p}

        '''
        pubKey = self.__diffiObj.gen_public_key()                                 # This is (gb mod p)
        sharedSecret = self.__diffiObj.gen_shared_key(long(senderObj["pubKey"]))  # This is (gab mop p)
        authInfo.setResponse()
        authInfo.setSharedSecret(sharedSecret)
        userPassHash = self.__findPasswordHashForUser(senderObj["user"])
        if userPassHash:
            gpowbw = self.__diffiObj.gen_gpowxw(pubKey, userPassHash)
            hash256 = self.__genShaX(hashlib.sha256(),str(gpowbw) + str(sharedSecret))
            hash384 = self.__genShaX(hashlib.sha384(),str(gpowbw) + str(sharedSecret))
            authInfo.setSha348(hash384)
            return pickle.dumps({
                "messageType": "initiateSecret",
                "hash": hash256,
                "pubKey": pubKey,
            })
        return False

    def __genShaX(self,sha,message):
        '''
            __genShaX(Object,String):
                    Input   : Object,Strint (THe sha object ie.sha256,384,512 and the message
                                            to be encrypted)
                    Output  : String (Returns the digest of the message)

        '''
        sha.update(message)
        return int(binascii.hexlify(sha.digest()), base=16)

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

    def __completeAuth(self,senderObj):
        '''
            __completeAuth(Object) :
                Input  : Object (The sender Objectified stream data from user
                                and Authentication info on server)
                Output : False -> If sha384 doesnt match
                        True -> Password is verified and session key is established

        '''
        if senderObj["user"] in self.__authDict:
            if senderObj["hash"] == self.__authDict[senderObj["user"]].getSha384() :
                print "User " + senderObj["user"] + " Connected"
                self.__sessionKeyDict[senderObj["user"]] = self.__authDict[senderObj["user"]].getSharedSecret()
                return True
            else:
                self.__authDict.pop(senderObj["user"])
        return False

    def __loadPickledData(self,message):
        '''
            __loadPickledData(String):
                Input  : String (Stream data from socket)
                Output : Object
                Purpose : Convert the stream data to object
        '''
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
            ret = self.__nowOnlineResponse(decryptedResponse)
        elif decryptedResponse["messageType"] == "quiz-response":
            ret = self.__challangeResponse(decryptedResponse)
        elif decryptedResponse["messageType"] == "complete":
            ret = self.__completeAuth(decryptedResponse)
        if not ret:
            self.__logErrors("Response from sender",address)
        return ret
