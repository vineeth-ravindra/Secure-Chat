import os
import sys
import pickle
import socket
import json
import hashlib 
import pymongo
import serverConnection

class client:
    def __init__(self):
        self.conn = serverConnection.connection()

    def run(self):
        print "Hello World"
        self.conn.establishConnection()

if __name__ == "__main__":
    c = client()
    c.run()
