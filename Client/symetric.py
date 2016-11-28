import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
class symetric:
    '''
    	symetric : Type -> class
    	purpose : Export interface to cryptography library to
    				perform AES (Symetric encryptio)
    	Features : Provides interface for
    				a) AES Encryption
    				b) AES Decryption
    				c) encryptor crypto object
    				d) decryptor crypto object
    '''
    def __init__(self,key):
        self.key = key

    def loadKey(self, key):
        self.key = key

    def getKey(self):
        return self.key

    def getEncryptor(self, iv):
        return Cipher(
            algorithms.AES(self.key),
            modes.CFB(iv),
            backend=default_backend()
        ).encryptor()

    def getDecryptor(self, iv):
        return Cipher(
            algorithms.AES(self.key),
            modes.CFB(iv),
            backend=default_backend()
        ).decryptor()

    def encryptMessage(self, message, encryptor):
        try:
            return encryptor.update(message) + encryptor.finalize()
        except:
            print "Error while symetric encryption"
            sys.exit(0)

    def decrypt(self, cipherText, decryptor):
        try:
            return decryptor.update(cipherText) + decryptor.finalize()
        except:
            print "Error While symetric decryption"
            sys.exit(0)