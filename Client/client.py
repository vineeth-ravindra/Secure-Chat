import sys, types
import serverConnection
import select

class client:
    def __init__(self):
        print "********************************"
        print "Welcome to the secure terminal"
        print "have a fun time :)"
        print "********************************\n"


    def __authenticateUser(self):
        '''
        __authenticateUser(None) :
            Input   : None
            Output  : Object (Instance of connection to server)
            Purpose : To authenticate user and set up connection with server
        '''
        userName = self.__readFromConsole("Enter Username: ").rstrip()
        password = self.__readFromConsole("Enter Password: ").rstrip()
        serverObj = serverConnection.connection(userName, password)
        if serverObj.establishConnection():
            return serverObj
        else :
            return self.__authenticateUser()

    def __writeMessage(self,message):
        ''' __writeMessage(String)
                Input   : String (Message to be desplayed on console
                Output  : None
                Purpose : Print message on terminal
        '''
        sys.stdout.write(message)
        sys.stdout.flush()

    def __readFromConsole(self,message):
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
        return msg

    def __flushManDocs(self):
        return "Usage \n**********\n " \
               "To message server type [ Server : <message> ]\n " \
               "To message client type [ Slient : <message> ]\n" \
                "Message to Server \n1. list \n2. Logout" \
               "**********\n"


    def __parseMessage(self, message):
        '''
             __parseMessage(String) :
                    Input  : String
                    Output : List -> If the message is recognizable
                            Boolean -> Message is unknown
        '''
        message = self.__parseMessageHelper(message.strip().lower())
        if type(message) is list:
            return message
        else :
            self.__writeMessage(message)
            return None


    def __parseMessageHelper(self, message):
        '''
             __parseMessageHelper(String) :
                    Input  : String
                    Output : List -> If the message is recognizable
                            Boolean -> Message is unknown
        '''
        message = message.split(":")
        if message[0] == "man":
            return self.__flushManDocs()
        elif message[0] == "server":
            return [True, message[1]]
        elif message[0] == "client":
            return [False, message[1]]
        else:
            return "Unknown Instruction\nPlease type man for usage instructions\n"


    def run(self):
        '''
            run(None):
                Input  : None
                Output : None
                Purpose : The point of entry to client program
                          Listens to console inputs for username password
                          Tries to establish connection with server, authenticates user
                          if user is authenticated on specific port to active connections
        '''
        self.__serverObj = self.__authenticateUser()

        while True:
            inputStreams = [self.__serverObj.getSock(), sys.stdin]
            self.__writeMessage("=>")
            ready_to_read, ready_to_write, in_error = \
                select.select(inputStreams, [], [])
            for iStream in ready_to_read:
                if iStream == self.__serverObj.getSock():
                    # incoming message from remote server, s
                    self.__serverObj.handleServerMessage()
                else:
                    # user entered a message
                    msg = self.__readFromConsole("")
                    msg = self.__parseMessage(msg)
                    if msg and msg[0]:
                        self.__serverObj.handleClientMessage(msg[1])
                    elif msg and not msg[0]:
                        print "Client Needs to do some work"

if __name__ == "__main__":
    c = client()
    c.run()
