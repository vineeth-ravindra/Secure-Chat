import sys
import serverConnection
import select

class client:
    def __init__(self):
        print "********************************"
        print "Welcome to the secure terminal"
        print "have a fun time :)"
        print "********************************\n\n"

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
        while True:
            print "Enter Username :"
            userName = sys.stdin.readline()
            print "Enter Password :"
            password = sys.stdin.readline()
            conn = serverConnection.connection(userName,password)
            if conn:
                break
            else :
                print "You know the drill ;) good luck this time!\n"
        self.__serverObj = conn
        self.__listenForInputs()

    def __listenForInputs(self):
        '''
            __listenForInputs(None):
                Input  : None
                Output : None
                Purpose : Not known as yet
        '''
        inputStreams = [self.sock, sys.stdin]
        ready_to_read, ready_to_write, in_error =  select.select(inputStreams, [], [])
        for sock in ready_to_read:
            if sock == self.sock:
                # incoming message from remote server, s
                data = sock.recv(4096)
                sys.stdout.flush()
            else:
                # user entered a message
                msg = sys.stdin.readline()
                print msg


if __name__ == "__main__":
    c = client()
    c.run()
