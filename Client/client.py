import sys
import serverConnection
import select

class client:
    def __init__(self):
        print "********************************"
        print "Welcome to the secure terminal"
        print "have a fun time :)"
        print "********************************\n"

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



    def __authenticateUser(self):
        '''
        __authenticateUser(None) :
            Input   : None
            Output  : Object (Instance of connection to server)
            Purpose : To authenticate user and set up connection with server
        '''

        userName = self.__readFromConsole("Enter Username: ").rstrip()
        password = self.__readFromConsole("Enter Password: ").rstrip()
        c = serverConnection.connection(userName, password).establishConnection()
        if c:
            return c
        else :
            self.__authenticateUser()

    def __readFromConsole(self,message):
        '''
                __readFromConsole(String) :
                    Input   : Message to be printed on screen
                    Output  : The string entered on console
                    Purpose : Write a message on console and read from same
                '''
        sys.stdout.write(message)
        sys.stdout.flush()
        inputStreams = [sys.stdin]
        ready_to_read, ready_to_write, in_error = \
            select.select(inputStreams, [], [])
        msg = sys.stdin.readline()
        return msg

    def __listenForInputs(self):
        '''
            __listenForInputs(None):
                Input  : None
                Output : None
                Purpose : Not known as yet
        '''
        print "Hello"


if __name__ == "__main__":
    c = client()
    c.run()
