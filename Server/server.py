import sys,socket,signal
import serverConnection

class server():
    '''
        Server{} :
            * Singleton Object
            * Opens socket on port 2424 and listens for connections from clients
        Note : Uses SERVER.conf to obtain config related information
    '''
    def __init__(self,port):
        '''
            __init__(None):
                Input   : None
                Output  : None
                Purpose : 1) Initialize the server
                          2) Create server socket and bind to port 2424
                          3) Listen to Active connections and authenticate Clients
                          4) Establish session keys with users
        '''
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error, msg:
            print "Failed to create socket"
            sys.exit(0)
        try:
            self.sock.bind(('', port))
        except socket.error , msg:
            print "Failed to bind to socket "
            print msg
            sys.exit(0)

    def __closeSocket(self):
        '''
            __closeSocket(None):
                    Input  : None
                    Output : None
                    Purpose : Safely terminate the server socket on
                              interrupt (ie. Ctrl+C  signal)

        '''
        self.sock.close()

    def __sendData(self,data,address):
        '''
            __sendData(String,tuple):
                Input   : String to be sent, Address to whom to be sent
                Output  : None
                Purpose : Send message to client

        '''
        try:
            self.sock.sendto(data, address)
        except Exception as e:
            print data
            print "Error while sending data to",address
            print e

    def run(self,connectionHandel):
        '''
            run(connectionHandel) :
                Input   : Connection (Addapter Object)
                Output  : None
                Purpose : Actively listen to the server 2424 port
                          and server clients based on message type

        '''
        print "Server running"
        while True:
            data , address = self.sock.recvfrom(4096)
            response, address = connectionHandel.parseData(data, address)
            try:
                if not isinstance(response, (int)):
                    self.__sendData(response, address)
            except Exception as e:
                print response
                print e

    def signal_handler(self,signal,frame):
        self.__closeSocket()
        sys.exit(0)

    def signal_handler(self, signal, frame):
        '''
            signal_handler(signal, frame):
                Input   : Interrupt signal
                Output  : None
                Purpose : Close server socket and exit

        '''
        print('You pressed Ctrl+C!')
        self.__closeSocket()
        sys.exit(0)


def terminalError():
    '''
        Output  : None
        Purpose : Log error in starting program
    '''
    print "Please provide sufficient arguments\nUsage : python server.py -sp <server port>"
    sys.exit(0)

def checkParameters():
    '''
        Output  : Number
        Purpose : Check if the input to the program is valid
    '''
    args = sys.argv
    if len(args) < 3:
        terminalError()
    if not args[1] == "-sp":
        terminalError()
    try:
        port = int(args[2])
    except Exception as e:
        terminalError()
    return port


if __name__ == "__main__":
    c = serverConnection.Connection()
    port = checkParameters()
    s = server(port)
    signal.signal(signal.SIGINT, s.signal_handler)
    s.run(c)