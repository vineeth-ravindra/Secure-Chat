import sys,socket,signal
import handelConnection

class server():
    '''
        Server{} :
            * Singleton Object
            * Opens socket on port 2424 and listens for connections from clients
        Note : Uses SERVER.conf to obtain config related information
    '''
    def __init__(self):
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
            self.sock.bind(('', 2424))
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
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def __sendData(self,data,address):
        '''
            __sendData(String,tupple):
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

    def signal_handler(self, signal, frame):
        '''
            signal_handler(signal, frame):
                Input   : Interrupt signal
                Output  : None
                Purpose : Close server socket

        '''
        print('You pressed Ctrl+C!')
        self.__closeSocket()
        sys.exit(0)

if __name__ == "__main__":
    c = handelConnection.Connection()
    s = server()
    s.run(c)