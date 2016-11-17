import os
import pickle
from random import randint

class connection:
    def __init__(self):
        print ""
        
    def nowOnlineResponse(self):
        rand = os.urandom(100)
        t = randint(512,1024)
        obj = {"message-type":"quiz","response":rand}
        ret = pickle.dumps(obj)
        return ret

    def _parseData(self,data,address):
        try:
            data = pickle.loads(data)
            if data["messageType"] == "now-online" :
                ret = self.nowOnlineResponse()
                return ret
        except Exception as e:
            print "Unsolicited message from address :"+ str(address)
            return False