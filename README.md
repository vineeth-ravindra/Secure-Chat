# SECURE UDP CHAT

### Secure UDP chat client allows users to communicate securely over a network. All data over the network is encrypted and the program is aimed providing the following features

* Perfect forward secracy
* Identity hiding
* Protection against week passwords
* Resistance to Denail Of Service Attacks 

#### The implimentation assumes that the server is secure and trusts information given by the server. If the server is compromised then the above promisses may not be valid any more

# Usage

* First generate server public and private RSA keys

```
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -outform PEM -out public_key.pem
```

*Copy the public_key.pem & private_key.pem into the Server folder and copy public_kep.pem into Client folder*

* Start server

```
python server.py -sp <server port>
```

* Start Client

```
python client.py -sp <server port>
```

* Supported Commands
```
* To List active users users : list
* To connect to user :connect
* To Send message : send <username> message
* To see all clients currently connected : connected
* Logout : logout
* See usage : man
```

#
# Dependencies 

* Python cryptography

```
 pip install cryptography
```

