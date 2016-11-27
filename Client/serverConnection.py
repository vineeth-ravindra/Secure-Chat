import socket
import pickle
import hashlib
import DH,binascii
import sys,json
import zlib
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

class connection:
    '''
        Connection Object is a Singleton.
        Purpose : 1) Establish connection with server
                  2) Obtain shared secret with server
                  3) Request Server for user Keys

    '''
    def __init__(self,username,password):
        '''
            __init__(None) :
                Input   : None
                Output  : None
                Purpose : Constructor which initializes the Connection object
                          1) Reads The CLIENT.conf file and sets up essential variables
                          2) Reads the public_key.pem file and obtains the servers public key
                          3) Creates socket to talk to server
        '''
        self.__username = username
        self.__convertPasswordToSecret(password)
        self.__diffi = DH.DiffieHellman()
        self.pubKey = self.__diffi.gen_public_key()
        self.__readConfigFile()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception as e:
            print "Error while creating socket",e
            sys.exit(0)

        with open("public_key.pem", "rb") as key_file:
            try:
                self.serverPublicKey = serialization.load_pem_public_key(
                    key_file.read(),
                    backend = default_backend())
            except Exception as e:
                print "Error while loading key ",e
                sys.exit(0)


    def __readConfigFile(self):
        ''' __readConfigFile(None) :
                   Input   : None
                   Output  : None
                   Purpose : Reads the CLIENT.conf file and extracts information from file
                             Information obtained include
                                   self.__salt       : Salt used to hash passwords
                                   self.__generator  : Generator used by Diffie Hellman
                                   self.__prime      : The Diffie Hellman Safe prime
        '''
        try:
            with open("CLIENT.conf", "rb") as conf_file:
                data = json.load(conf_file)
                self.__prime = data["prime"]
                self.__salt = data["salt"]
                self.__generator = data["generator"]

        except Exception as e:
            print "Error While reading Config File",e
            sys.exit(0)


    def __sendData(self,obj):
        ''' __sendData(String) :
                        Input   : String
                        Output  : None
                        Purpose : Sends the given String to the server
        '''
        try:
            self.sock.sendto(obj,('',2424))
        except Exception as e:
            print "Error while sending data"

    def __recvData(self):
        ''' __recvData(None) :
                        Input   : None
                        Output  : None
                        Purpose : Receives data from the server once data becomes
                                    avilable on socket
        '''
        data = None
        while data is None:
            data = self.sock.recv(4096)
        data = pickle.loads(data)
        return data

    def __encryptMessageWithServerPubKey(self, message):
        ''' __encryptMessageWithServerPubKey(String) :
                        Input   : String
                        Output  : String (encrypted)
                        Purpose : Given a string encrypts the data with the servers
                                   Public Key and returns the encrypted data
       '''
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


    def __sayHello(self):
        '''__sayHello(None) :
                    Input          : None
                    Output         : None
                    Purpose        : First step of Augmented string password protocol to inform server
                                     the client is now online and it requests to establish a shared
                                     secret
                    Message Format : { messageType :now-online,
                                        username
                                     }
        '''
        desObj = {"messageType":"now-online","user":self.__username}
        desObj = pickle.dumps(desObj)
        self.__sendData(desObj)

    def __puzzleSolve(self,data):
        ''' __puzzleSolve(String):
                Input  : String (The response from server when requested to initiate connection)
                Output :    Object -> { username ,
                                        S{user public key ,Computed Response to challenge},
                                        messageType
                                      }
                            False -> If the solution to challenge does not exist
        '''
        response = data["challange"]
        obj = {}
        for x in range (-1,65537):
            sha = hashlib.sha256()
            sha.update(response+str(x))
            if sha.digest() == data["answer"]:
               obj["answer"] = x
               obj["pubKey"] = self.pubKey
               obj = pickle.dumps(obj)
               obj = self.__encryptMessageWithServerPubKey(obj)
               return pickle.dumps({
                   "user" :self.__username,
                   "encoded":obj,
                   "messageType":"quiz-response"
               })
        return False

    def __convertPasswordToSecret(self,password):
        ''' __convertPasswordToSecret (String):
                           Input   : Password of User
                           Output  : None
                           Purpose : Converts test password to secret (2^w mod p)
                                     Once the secret is generated the passwords is forgotten
        '''
        sha = hashlib.sha256()
        sha.update(password+str(self.__salt))
        hash = sha.digest()
        hash = int(binascii.hexlify(hash), base=16)
        try :
            self.__passSecret = pow(self.__generator, hash, self.__prime)
        except Exception as e:
            print e
        password = None


    def __establishSecret(self,data):
        """__establishSecret(String):
            Input   : String (Response from server with the for the sent response,
                      Contains servers public Key Diffie Hellman key
            Output  :
                        1) False if the hash sent does not match
                        2)Object containing sha384 of g^bw modp and g^ab
            Purpose : Verify the users password is correct and complete the password
                        authentication by sending the sha384 of g^bw modp and g
            Message Format :
                                {messageType: est , user , S{hash} }
        """
        serverPubKey = long(data["pubKey"])
        sharedSecret = self.__diffi.gen_shared_key(serverPubKey)
        gpowbw =  self.__diffi.gen_gpowxw(serverPubKey,self.__passSecret)
        if not self.__verifyPassword(gpowbw,sharedSecret,long(data["hash"])):
            return False
        hash = self.__gen384Hash(gpowbw,sharedSecret)
        hash = self.__encryptMessageWithServerPubKey(str(hash))
        obj = {
            "messageType" : "complete",
            "hash" : hash,
            "user" : self.__username
        }
        return pickle.dumps(obj)

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

    def __verifyPassword(self,gpowbw,sharedSecret,serverHash):
        '''
            __verifyPassword(float,float,int) :
                Input   : g^bw mod p, g^ab mod p , sha256(g^bw mod p + g^ab mod p)
                Output  : None
                Purpose : Verify if the password enterd by the user matches that at the
                            server
        '''
        sha = hashlib.sha256()
        sha.update(str(gpowbw) + str(sharedSecret))
        if  int(binascii.hexlify(sha.digest()), base=16) == serverHash:
            print "Login Success"
        else :
            print "Invalid username password please try again"
            return False



    def establishConnection(self):
        ''''establishConnection(None) : Public method
                Input   : None
                Output  : None
                Purpose : Control to initial connection with server

        '''
        # Step 1 : Say Hello 
        self.__sayHello()
        data = self.__recvData()
        # Step 2 : Send Response to challange
        data = self.__puzzleSolve(data)
        self.__sendData(data)
        data = self.__recvData()
        # Step 3 : Generate Shared Secret and complete connection
        data = self.__establishSecret(data)
        if not data:
            return False
        else:
            self.__sendData(data)
        return True