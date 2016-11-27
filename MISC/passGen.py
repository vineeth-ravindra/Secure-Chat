# Created By Vineeth
'''
        Use this file to create the config file
        The config file stores hash of all passwords and the salt information
'''

import os
import hashlib
import binascii
import json
users = ["Alice:password","Bob:Her0sRu1e"]

primes = {
    # 1536 bits
    "prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
    "generator": 2
}


def generatePasswordFile(users):
    '''
         generatePasswordFile(List) :
                    Input   : List (List of username:password)
                    Output : None
                    Purpose : Given a list of username passwords, Writes to a
                              file a JSON of the same The generated file is used as
                              the server config file
    '''
    obj = {}
    salt = int(binascii.hexlify(os.urandom(15)), base=16)
    obj["salt"] = salt
    for user in users:
        sha = hashlib.sha256()
        user = user.split(":")
        sha.update(user[1]+str(salt))
        hash = sha.digest()
        hash =int(binascii.hexlify(hash), base=16)
        secret = pow(primes["generator"],hash,primes["prime"])
        obj[user[0]] = secret

    with open('SERVER.conf', 'w') as outfile:
        json.dump(obj, outfile)

generatePasswordFile(users)



# ****************
# Read File
# ****************
# with open("SERVER.conf") as json_file:
#     json_data = json.load(json_file)
#     print json_data["Bob"]