import socket
import pickle
import hashlib
import DH,binascii
import sys,json,select
import zlib,os
from symetric import symetric
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
        self.__readConfigFile()
        self.__username = username
        self.__destHostKey = {}                     # {Address,Key}
        self.__convertPasswordToSecret(password)
        self.__diffi = DH.DiffieHellman()
        self.__serverNonceHistory = []
        self.__addressUserNameMap = {}
        self.__pubKey = self.__diffi.gen_public_key()

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

    def getSock(self):
        return self.sock

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


    def __sendData(self,message,address = ('',2424)):
        ''' __sendData(String) :
                        Input   : String(Message to be sent to server)
                        Output  : None
                        Purpose : Sends the given String to the server
        '''
        try:
            self.sock.sendto(message, address)
        except Exception as e:
            print "Error while sending data",e

    def __recvData(self):
        ''' __recvData(None) :
                        Input   : None
                        Output  : None
                        Purpose : Receives data from the server once data becomes
                                    available on socket
        '''
        data = None
        try:
            self.sock.settimeout(5)
            while data is None:
                data, address = self.sock.recvfrom(4096)
        except Exception as e:
            self.__serverOffline()
            return [False, False]
        data = pickle.loads(data)
        return data, address

    def __encryptMessageWithServerPubKey(self, message):
        ''' __encryptMessageWithServerPubKey(String) :
                        Input   : Message to be encrypted with public key of server
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
        encodedObject = self.__encryptMessageWithServerPubKey(
                                    pickle.dumps({
                                        "user"          : self.__username,
                                        "messageType"   : "now-online",
                                    }))
        encodedObject = {
                "user"      : self.__username,
                "message"   : encodedObject,
                "type"      : "asym"
        }
        self.__sendData(pickle.dumps(encodedObject))

    def __puzzleSolve(self, data):
        ''' __puzzleSolve(String):
                Input  : String (The response from server when requested to initiate connection)
                Output :    Object -> { username ,
                                        S{user public key ,Computed Response to challenge},
                                        messageType
                                      }
                            False -> If the solution to challenge does not exist
        '''
        response = data["challange"]
        for x in range (-1,65537):
            sha = hashlib.sha256()
            sha.update(response+str(x))
            if sha.digest() == data["answer"]:
               message = pickle.dumps({
                   "answer"      : x,
                   "pubKey"      : self.__pubKey,
                   "messageType" : "quiz-response",
                   "user"        : self.__username,
               })
               return pickle.dumps({
                   "message"    : self.__encryptMessageWithServerPubKey(message),
                   "type"       : "asym"
               })
        return False

    def __convertPasswordToSecret(self, password):
        ''' __convertPasswordToSecret (String):
                           Input   : Password of User
                           Output  : None
                           Purpose : Converts test password to secret (2^w mod p)
                                     Once the secret is generated the passwords is forgotten
        '''
        sha = hashlib.sha256()
        sha.update(password + str(self.__salt))
        hash = sha.digest()
        hash = int(binascii.hexlify(hash), base=16)
        try :
            self.__passSecret = pow(self.__generator, hash, self.__prime)
        except Exception as e:
            print "Unable to convert password to secret ",e
        password = None


    def __establishSecret(self, data):
        """__establishSecret(String):
            Input   : String (Response from server with the for the sent response,
                      Contains servers public Key Diffie Hellman key
            Output  :
                        1) False if the hash sent does not match
                        2) Object containing sha384 of g^bw modp and g^ab
            Purpose : Verify the users password is correct and complete the password
                        authentication by sending the sha384 of g^bw modp and g
            Message Format :
                                {messageType: complete , user , hash }
        """
        serverPubKey = long(data["pubKey"])
        self.__sharedSecret = self.__diffi.gen_shared_key(serverPubKey)
        gpowbw =  self.__diffi.gen_gpowxw(serverPubKey,self.__passSecret)
        if self.__verifyPassword(gpowbw,self.__sharedSecret,long(data["hash"])) is False:
            return False
        hash = self.__gen384Hash(gpowbw,self.__sharedSecret)
        objToEnc = pickle.dumps(
            {
                "messageType" : "complete",
                "hash"        : hash,
                "user"         : self.__username
            })
        obj = {
            "message"   : self.__encryptMessageWithServerPubKey(objToEnc),
            "type"      : "asym"
        }
        self.__sharedSecret = str(self.__sharedSecret)[0:16]
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
        hash = int(binascii.hexlify(sha.digest()), base=16)
        if hash  == serverHash:
            print "Login Success"
        else :
            print "Invalid username password please try again"
            return False

    def __serverOffline(self):
        '''
            __serverOffline(None):
                Input   : None
                Output  : None
                Purpose : Handle if server is offline
        '''
        self.__writeMessage("\nServer not responding check input and try again later\n")

    def __listUsers(self):
        '''
            listUsers(None) :
                    Input   : None
                    Output  : List (List of all users connected to the server)
                    Purpose : Gives the list of all users currently connected to server
        '''

        iv = os.urandom(16)
        message  = self.__encryptSymetric(
            self.__sharedSecret,iv,
            pickle.dumps(
                {
                    "request"   : "list",
                    "Nonce"     : str(int(binascii.hexlify(os.urandom(8)), base=16)),
                    "user"      : self.__username,
                }))
        obj = {
            "message"   : message,
            "IV"        : iv,
            "type"      : "sym"
        }
        self.__sendData(pickle.dumps(obj))
        data, address = self.__recvData()
        if data is False:
            self.__serverOffline()
            return
        message = self.__decryptSymetric(self.__sharedSecret,data["IV"],data["message"])
        message = pickle.loads(message)
        print "Users connected are ", message["users"]


    def __decryptSymetric(self, key, iv, message):
        '''
            __decryptSymetric(String,String):
                    Input  : String, String (The  Encryped message and the IV
                    Output : Decrypted message
                    Purpose : Decrypt message sent by server
        '''

        s = symetric(key)
        decryptor = s.getDecryptor(iv)
        return s.decrypt(message, decryptor)

    def __encryptSymetric(self, key, iv, message):
        '''
            __encryptSymetric(String,String):
                    Input  : String, String (Key, message to be encrypted and the IV)
                    Output : Encrypted message with session key
                    Purpose : Encrypt message with session keys of client and server(Ksx)
        '''

        s = symetric(key)
        encryptor = s.getEncryptor(iv)
        return s.encryptMessage(message, encryptor)


    def establishConnection(self):
        ''''establishConnection(None) : Public method
                Input   : None
                Output  : None
                Purpose : Control to initial connection with server

        '''
        # Step 1 : Say Hello
        self.__sayHello()
        data, address = self.__recvData()
        if data is False:
            return
        # Step 2 : Send Response to challange
        data = self.__puzzleSolve(data)
        self.__sendData(data)
        data, address = self.__recvData()
        if data is False:
            return
        # Step 3 : Generate Shared Secret and complete connection
        data = self.__establishSecret(data)
        if not data:
            return False
        self.__sendData(data)
        return True

    def __writeMessage(self, message):
        ''' __writeMessage(String)
                Input   : String (Message to be desplayed on console
                Output  : None
                Purpose : Print message on terminal
        '''
        sys.stdout.write(message)
        sys.stdout.flush()

    def __readFromConsole(self, message):
        '''
                __readFromConsole(String) :
                    Input   : Message to be printed on screen
                    Output  : The string entered on console
                    Purpose : Write a message on console and read from same
        '''
        self.__writeMessage(message)
        inputStreams = [sys.stdin]
        ready_to_read, ready_to_write, in_error = \
            select.select(inputStreams, [], [])
        msg = sys.stdin.readline()
        return msg.strip()

    def __setDestHostKey(self, message):
        '''
            __setDestHostKey(Object) :
                Input   : Object (The objectified string after symmetrically decrypted with server session key)
                Output  : None
                Purpose : Set the session key to chat with remote host
        '''
        if message["Nonce"] in self.__serverNonceHistory:
            return
        self.__serverNonceHistory.append(message["Nonce"])
        print message["user"]
        choice = self.__readFromConsole("\nUser "+message["user"][0] +" Wishes to talk to you\n"
                                                        "Want to accept Connection? (Y/N) ")
        if choice.lower() == "y":
            self.__writeMessage("\n User "+message["user"][0]+ " connected \n")
            self.__destHostKey[message["user"][0]] = [message["user"][1], message["Key"]]           #     Address, Key
            self.__addressUserNameMap[message["user"][1]] = message["user"][0]
        if choice.lower() == "n":
            self.___disconnectClient("refused",message["Key"],message["user"][1])

    def __connectionTeaerDown(self, clientMessage, address, message):
        '''
            __connectionTeaerDown(Object,tupple,String):
                Input   : The Object sent by client, The address of Host, and message to be logged on terminal
                Output  : None
                Purpose : Tare down a connection
        '''
        if clientMessage["Nonce"] not in self.__serverNonceHistory:
            self.__serverNonceHistory.append(clientMessage["Nonce"])
            self.__writeMessage(message)
            if clientMessage["user"] in self.__destHostKey:
                self.__destHostKey.pop(clientMessage["user"])
                self.__addressUserNameMap.pop(address)

    def __printChatMessage(self, clientMessage):
        '''
            __printChatMessage(Object):
            Input   : Object received from client
            Output  :   None
            Purpose : Print the chat message onto terminal
        '''
        if clientMessage["Nonce"] not in self.__serverNonceHistory:
            self.__writeMessage("\n" + clientMessage["user"] + ": " + clientMessage["chat"] + "\n")
            self.__serverNonceHistory.append(clientMessage["Nonce"])

    def __chatSessionMessages(self, serverObj, address):
        '''
        __chatMessage(Object)
            purpose : Handle chat message
        '''
        if serverObj["message"] == "client":
            clientMessage = self.__decryptSymetric(self.__destHostKey[self.__addressUserNameMap[address]][1],
                                                   serverObj["IV"],serverObj["data"])
            clientMessage = pickle.loads(clientMessage)
            if clientMessage["message"] == "chat":
                self.__printChatMessage(clientMessage)
            elif clientMessage["message"] == "refused":
                self.__connectionTeaerDown(clientMessage,address,
                                           "Connection was refused by " + clientMessage["user"] + "\n")
            elif clientMessage["message"] == "logout":
                self.__connectionTeaerDown(clientMessage, address,
                                           clientMessage["user"]+" Just left\n")


    def handleServerMessage(self):
        '''
            handleServerMessage(None)
                Input   : None
                Output  : None
                Purpose : Handle clients requests to talk to server
        '''
        serverObj, address = self.__recvData()
        if serverObj is False:
            return
        try:
            response = pickle.loads(self.__decryptSymetric(self.__sharedSecret,
                                                      serverObj["IV"],serverObj["message"]))
        except Exception as e:
            return self.__chatSessionMessages(serverObj, address)
        if  "Nonce" in response and \
                        response["Nonce"] not in self.__serverNonceHistory:
            if response["message"] == "disconnect":
                self.logout()
                print "Server just kicked you out"
                sys.exit(0)
            if response["message"] == "talkto":
                self.__setDestHostKey(response)

    def ___disconnectClient(self, message, key, address):
        '''
            ___disconnectClient(String,String,tupple):
                Input   :  The message to be sent for disconnection, The Key to encrypt message,
                            Address to whom the message is to be send
                Output  : None
                Purpose : Disconnect connected client

        '''
        iv = os.urandom(16)
        obj = self.__encryptSymetric(key, iv,
                                     pickle.dumps({
                                         "message"  : message,
                                         "user"     : self.__username,
                                         "Nonce"    : str(int(binascii.hexlify(os.urandom(8)), base=16))
                                     }))
        self.__sendData(pickle.dumps({
            "message"   : "client",
            "data"      : obj,
            "IV"        : iv,
        },
        ), address)


    def __talkToHost(self):
        '''
            __talkToHost(None) :
                Input   : (None)
                Output  : (None)
                Purpose : Request Session key to server to talk to remote host and send same to remote host
        '''
        destHost = self.__readFromConsole("Whom do you wish to speak to :")
        if destHost in self.__destHostKey:
            self.__writeMessage("User already connected\n")
            return
        iv = os.urandom(16)
        obj = pickle.dumps({
            "request"              : "talk",
            "userDestination"      : destHost,
            "Nonce"                : str(int(binascii.hexlify(os.urandom(8)), base=16)),
            "user"                 : self.__username
        })
        encryptedMessage = self.__encryptSymetric(self.__sharedSecret, iv, obj)
        # Send data to server : Request Ticket from server
        self.__sendData(
            pickle.dumps({
                          "message" : encryptedMessage,
                          "IV"      : iv,
                          "type"    : "sym"
                      }))
        message, address = self.__recvData()
        if message is False:
            return
        message = pickle.loads(self.__decryptSymetric(self.__sharedSecret,message["IV"],message["message"]))
        # Send data to Client : Send token received from client
        self.__sendData(
                pickle.dumps({"message": message["ticket"], "IV": message["IV"] }),
            message["address"])
        self.__addressUserNameMap[message["address"]] = destHost
        self.__destHostKey[destHost] = [message["address"], message["Key"]]                 # Username , Address, Key


    def logout(self):
        '''
            logout(None):
                Input   : None
                Output  : None
                Purpose : Disconnect from all connected users and terminate client

        '''
        for user in self.__destHostKey :
            self.___disconnectClient("logout",self.__destHostKey[user][1],self.__destHostKey[user][0])
        iv = os.urandom(16)
        message = self.__encryptSymetric(
            self.__sharedSecret, iv,
            pickle.dumps({
                "request"   : "logout",
                "Nonce"     : str(int(binascii.hexlify(os.urandom(8)), base=16)),
                "user"      : self.__username
          }))
        obj = {
            "message"   : message,
            "IV"        : iv,
            "type"      : "sym"
        }
        self.__sendData(pickle.dumps(obj))
        self.__writeMessage("It was a pleasure having you here\nGet back soon:)\n")
        sys.exit(0)

    def handleClientMessage(self, message):
        '''
            handleClientMessage(String):
                Input  : The message received from other client
                Output : None
                Purpose : Parse the users input from the terminal and perform appropriate
                            function to communicate with server
        '''
        message = message.strip()
        if message == "list":
            self.__listUsers()
        elif message == "connect":
            self.__talkToHost()
        elif message == "logout":
            self.logout()
        elif message == "connected":
            self.__showConnectedHosts()
        else:
            print "Unknown Message"

    def __showConnectedHosts(self):
        '''
            __showConnected(None):
                Input   : None
                Output  : None
                Purpose : Print the list of all users connected to  client
        '''
        self.__writeMessage("Connected Hosts :" + str(self.__destHostKey.keys()) + "\n")

    def sendMessageToClient(self,message):
        '''
            sendMessageToClient(String):
                Input   : String
                Output  : None
                Purpose : Send chat message to client
        '''
        user = message[0]
        message = " ".join(message[1:])
        iv = os.urandom(16)
        if not self.__destHostKey or user not in self.__destHostKey:
            self.__writeMessage("Client not connected\n")
            return
        obj = self.__encryptSymetric(self.__destHostKey[user][1] ,iv,
                                     pickle.dumps({
                                         "message":"chat",
                                         "chat"   :message,
                                         "user"   :self.__username,
                                         "Nonce": str(int(binascii.hexlify(os.urandom(8)), base=16))
                                       }))
        self.__sendData(pickle.dumps({
                "message"   :   "client",
                "IV"        :   iv,
                "data"      :   obj,
                }
            ), self.__destHostKey[user][0])