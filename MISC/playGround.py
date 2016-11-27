import os
import sys
import pickle
import socket
import json
import hashlib 
import pymongo
from datetime import datetime

# ***************************
# Part of opening connection and sending i am online
# ***************************

# desObj = {'messageType':"now-online"}

# destObj = pickle.dumps(desObj)
# try:
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# except e:
#     print "Error while creating socket"

# desObj = {'messageType':"now-online"}

# destObj = pickle.dumps(desObj)
# try:
#     sock.sendto(destObj,('',2424))
# except Exception as e:
#     print "Error while sending data"

# data = sock.recv(4096)

# print data

# ***************************
# End End End End End End End End End 
# ***************************



# ***************************
# Generating random n digit numbers
# ***************************
# a = ["".join(seq) for seq in itertools.product("01", repeat=3)]
# var = os.urandom(100)
# t1 = os.urandom(3)
# m =  hashlib.sha256()
# m.update(var)
# print m.digest()
# import itertools
# from random import randint
# print(randint(0,9))
# ***************************
# End End End End End End End End End 
# ***************************


# ***************************
# Tests to connect to mongo client
# ***************************
client = pymongo.MongoClient()
db = client.MongoLabs
db.test.create_index("date", expireAfterSeconds=15)
db.test.insert({"hahaha":"hello world", "date": datetime.utcnow()})