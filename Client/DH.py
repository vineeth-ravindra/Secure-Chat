import os
import binascii
import hashlib

primes = {
    # 1536 bits
    "prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
    "generator": 2
}

class DiffieHellman:
    """ Class to represent the Diffie-Hellman key exchange protocol """
    def __init__(self):
        self.p = primes["prime"]
        self.g = primes["generator"]
        self.__a = int(binascii.hexlify(os.urandom(32)), base=16)

    def get_private_key(self):
        # returns the secret a
        return self.__a

    def gen_public_key(self):
        # calculate G^a mod p and returns the same
        return pow(self.g, self.__a, self.p)

    def gen_shared_key(self, other_contribution):
        # calculate the shared key G^ab mod p
        try:
            self.shared_key = pow(other_contribution, self.__a, self.p)
            return hashlib.sha256(str(self.shared_key).encode()).hexdigest()
        except Exception as e:
            print "Error during determining g^ab mod p"

    def gen_gpowxw(self,password_hash):
        # calculate the shared key G^bw mod p
        try:
            self.shared_key = pow(password_hash, self.__a, self.p)
            return hashlib.sha256(str(self.shared_key).encode()).hexdigest()
        except Exception as e:
            print "Error during determining g^ab mod p"