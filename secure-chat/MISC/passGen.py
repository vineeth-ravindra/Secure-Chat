# Created By Vineeth
'''
        Use this file to create the config file
        The config file stores hash of all passwords and the salt information
'''

import os
import hashlib
import binascii
import json
users = ["alice:password", "bob:Her0sRu1e", "tim:mommy"]

primes = {
    # 1536 bits
    "prime": 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919,
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
    salt = 1055321098333477550561901414932439633
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