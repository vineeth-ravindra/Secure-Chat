# Created By Vineeth
# Use this file to create the config file
# The config file stores hash of all passwords and the salt information


import os
import hashlib
users = ["Alice:password","Bob:Her0sRu1e"]
def generatePasswordFile(users):
    with open('SERVER.conf', 'a') as f:
        salt = os.urandom(15)
        f.write("SALT:+++:"+salt+"\n")
        for user in users:
            sha = hashlib.sha256()
            user = user.split(":")
            sha.update(user[1]+salt)
            hash = sha.digest()
            f.write(user[0]+":+++:"+hash+"\n")

generatePasswordFile(users)



# ****************
# Read File
# ****************
# with open("server.conf") as f:
#     x = f.read()
#     x = x.split('\n')
#     for i in x:
#         print i.split(":+++:")[0]