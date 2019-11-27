'''
@Reference:
https://tools.ietf.org/html/draft-irtf-cfrg-vrf-01
'''

import hashlib
import binascii
import operator
import math
import sys
from sys import argv
from crypto_rsa import Crypto_RSA

'''Returns the number of bytes necessary to store the integer n.'''


def integer_byte_size(int_num):
    byte_size, remainder = divmod(integer_bit_size(int_num), 8)
    if ((remainder != 0) or (int_num == 0)):
        byte_size += 1
    return byte_size


'''Returns the number of bits necessary to store the integer n.'''


def integer_bit_size(int_num):
    if (int_num == 0):
        return 1
    bit_size = 0
    while int_num:
        bit_size += 1
        int_num >>= 1
    return bit_size


'''Return the ceil integer of a/b.'''


def integer_ceil(num_a, num_b):
    ceil, remainder = divmod(num_a, num_b)
    if remainder:
        ceil += 1
    return ceil


'''
    RSA Public Key class
'''


class RSA_PublicKey(object):
    # the usage of __slots__ to tell Python not to use a dict,
    # and only allocate space for a fixed set of attributes.
    __slots__ = ('n', 'e', 'bit_size', 'byte_size')

    def __init__(self, n, e):
        self.n = n
        self.e = e
        self.bit_size = integer_bit_size(n)
        self.byte_size = integer_byte_size(n)

    # __repr__ is a built-in function used to compute the "official" string reputation of an object
    def __repr__(self):
        return ('<RSA_PublicKey n: %d e: %d bit_size: %d byte_size: %d>'
                % (self.n, self.e, self.bit_size, self.byte_size))

    def rsaep(self, m):
        '''
            Function: RSA Encryption Primitive (RSAEP) as defined in Section 5.1.1 of [RFC8017]
            Define: RSAEP ((n, e), m)
                @Input:
                    (n, e): RSA public key
                    m: message representative, an integer between 0 and n - 1
                @Output:
                    c: ciphertext representative, an integer between 0 and n - 1
        '''
        # If the message representative m is not between 0 and n - 1,
        # output "message representative out of range" and stop.
        if not (0 <= m <= self.n - 1):
            raise Exception("m not within 0 and n - 1")
        # Let c = m^e mod n
        c = pow(m, self.e, self.n)
        # output c.
        return c

    def rsavp1(self, s):
        '''
            Function: RSA verification primitive as defined in Section 5.2.2 of [RFC8017]
            Define: RSAVP1 ((n, e), s)
                @Input:
                    s: signature representative, an integer between 0 and n - 1
                    (n, e): RSA public key
                @Output:
                    m: message representative, an integer between 0 and n - 1
        '''
        # If the signature representative s is not between 0 and n - 1,
        # output "signature representative out of range" and stop.
        if not (0 <= s <= self.n - 1):
            raise Exception("s not within 0 and n - 1")
        # return m = s^e mod n by call rsaep()
        return self.rsaep(s)


'''
    RSA Private Key class
'''


class RSA_PrivateKey(object):
    # the usage of __slots__ to tell Python not to use a dict,
    # and only allocate space for a fixed set of attributes.
    __slots__ = ('n', 'd', 'bit_size', 'byte_size')

    def __init__(self, n, d):
        self.n = n
        self.d = d
        self.bit_size = integer_bit_size(n)
        self.byte_size = integer_byte_size(n)

    # __repr__ is a built-in function used to compute the "official" string reputation of an object
    def __repr__(self):
        return ('<RSA_PrivateKey n: %d d: %d bit_size: %d byte_size: %d>'
                % (self.n, self.d, self.bit_size, self.byte_size))

    def rsadp(self, c):
        '''
            Function: RSA Decryption Primitive (RSADP) as defined in Section 5.1.2 of [RFC8017]
            Define: RSADP ((n, d), m)
                @Input:
                    (n, d): RSA private key
                    c: ciphertext representative, an integer between 0 and n - 1
                @Output:
                    m: message representative, an integer between 0 and n - 1
        '''
        # If the ciphertext representative c is not between 0 and n - 1,
        # output "ciphertext representative out of range" and stop.
        if not (0 <= c <= self.n - 1):
            raise Exception("c not within 0 and n - 1")

        # let m = c^d mod n.
        m = pow(c, self.d, self.n)
        # output m
        return m

    def rsasp1(self, m):
        '''
            Function: RSA signature primitive as defined in Section 5.2.1 of [RFC8017]
            Define: RSAVP1 ((n, e), m)
                @Input:
                    m: message representative, an integer between 0 and n - 1
                    (n, e): RSA private key
                @Output:
                    s: signature representative, an integer between 0 and n - 1
        '''
        # If the message representative m is not between 0 and n - 1,
        # output "message representative out of range" and stop.
        if not (0 <= m <= self.n - 1):
            raise Exception("m not within 0 and n - 1")

        # return s = m^d mod n by call rsaep()
        return self.rsadp(m)


'''
    RSA Full Domain Hash VRF (RSA-FDH-VRF)
'''


class RSA_FDH_VRF(object):

    @staticmethod
    def i2osp(x, xLen):
        '''
        Coversion of a nonnegative integer x to an octet string as defined in Section 4.1 of [RFC8017]
        big-endian representation with length x_len.
        @Input:
            x: nonnegative integer to be converted
            xLen: intended length of the resulting octet string
        @Output:
            X: corresponding octet string of length xLen

        '''
        # If x >= 256^xLen, output "integer too large" and stop.
        if (x >= 256 ** xLen):
            raise ValueError("integer too large")
        # get hex value of integer
        hex_x = hex(x)[2:]

        # transfer to big-endian representation
        if hex_x[-1] == 'L':
            hex_x = hex_x[:-1]
        if len(hex_x) & 1 == 1:
            hex_x = '0%s' % hex_x

        # convert to the binary data represented by the hexadecimal string
        X = binascii.unhexlify(hex_x)

        # Output the octet string
        return b'\x00' * int(xLen - len(X)) + X

    @staticmethod
    def os2ip(X):
        '''
        Coversion of an octet string to a nonnegative integer as defined in Section 4.2 of [RFC8017]
        @Input:
            X: octet string to be converted
        @Output:
            x: corresponding nonnegative integer
        '''
        # Return the hexadecimal representation of the binary data
        x = binascii.hexlify(X)
        return int(x, 16)

    @staticmethod
    def mgf1(mgf_seed, mask_len, hash_type="SHA1"):
        '''
        Mask Generation Function based on a hash function as defined in Section B.2.1 of [RFC8017]
        @Input:
            mgs_seed - seed from which mask is generated, an octet string
            mask_len - intended length in octets of the mask, at most 2^32 hLen
            hash_type - the digest hash function to use, default is SHA1
        Outout:
            mask: an octet string of length mask_len
        '''
        hash_class = hashlib.new(hash_type)
        # get hash length given hash function
        h_len = hash_class.digest_size

        # If maskLen > 2^32 hLen, output "mask too long" and stop.
        if mask_len > 0x10000:
            raise ValueError('mask too long')

        # Let T be the empty octet string.
        T = b''
        hash_class.update(mgf_seed.encode(encoding='UTF-8'))

        # For counter i from 0 to \ceil (mask_len / h_len) - 1
        for i in range(0, integer_ceil(mask_len, h_len)):
            # Convert counter to an octet string C of length 4 octets
            C = RSA_FDH_VRF.i2osp(i, 4)

            # Concatenate the hash of the seed mgfSeed and C to the octet string T
            # T = T || Hash(mgfSeed || C)
            # temp = (mgf_seed + C.decode(encoding='UTF-8')).encode(encoding='UTF-8')
            # temp = b"".join([mgf_seed.encode(encoding='UTF-8'), C])
            hash_class.update(C)
            # T = T + hash_class.digest()
            T = b"".join([T, hash_class.digest()])

        # Output the leading maskLen octets of T as the octet string mask.
        return T[:mask_len]

    @staticmethod
    def prove(private_key, alpha, k):
        '''
        RSA-FDH-VRF Proving
        @Input:
            private_key - RSA private key
            alpha - VRF hash input, an octet string
            k - intended length in octets of the mask, at most 2^32 hLen
        Outout:
            pi - proof, an octet string of length n
        '''
        # k is the length of pi
        EM = RSA_FDH_VRF.mgf1(alpha, k - 1)
        m = RSA_FDH_VRF.os2ip(EM)
        s = private_key.rsasp1(m)
        pi = RSA_FDH_VRF.i2osp(s, k)
        return pi

    @staticmethod
    def proof2hash(pi, hash_type="SHA1"):
        '''
        RSA-FDH-VRF Proof To Hash
        @Input:
            pi - proof, an octet string of length k
        Outout:
            beta - VRF hash output, an octet string of length hLen
        '''
        hash_class = hashlib.new(hash_type)
        hash_class.update(pi)
        beta = hash_class.digest()
        return beta

    @staticmethod
    def verifying(public_key, alpha, pi, k):
        '''
        RSA-FDH-VRF Verifying
        @Input:
            (n, e) - RSA public key
            alpha - VRF hash input, an octet string
            pi - proof to be verified, an octet string of length n
            k - intended length in octets of the mask, at most 2^32 hLen
        Outout:
            beta - VRF hash output, an octet string of length hLen
        '''
        s = RSA_FDH_VRF.os2ip(pi)
        m = public_key.rsavp1(s)
        EM = RSA_FDH_VRF.i2osp(m, k - 1)
        EM_ = RSA_FDH_VRF.mgf1(alpha, k - 1)
        if EM == EM_:
            return "VALID"
        else:
            return "INVALID"


def get_key_numbers_from_files():
    # define key_pairs dictionary
    key_numbers = {}
    load_public_key_bytes = Crypto_RSA.load_key_bytes('public_key_file')
    load_private_key_bytes = Crypto_RSA.load_key_bytes('private_key_file')

    reload_publick_key = Crypto_RSA.load_public_key(load_public_key_bytes)
    # print(reload_publick_key.public_numbers())

    reload_private_key = Crypto_RSA.load_private_key(load_private_key_bytes, 'samuelxu999')
    # print(reload_private_key.private_numbers().d)

    # genereate key pairs numbers
    private_numbers = reload_private_key.private_numbers()
    public_numbers = reload_publick_key.public_numbers()

    # add private key value - x
    key_numbers['n'] = public_numbers.n
    key_numbers['e'] = public_numbers.e
    key_numbers['d'] = private_numbers.d
    key_numbers['key_size'] = reload_private_key.key_size

    return key_numbers


if __name__ == "__main__":
    if len(argv) < 2:
        print("USAGE: python RSA_VRF.py [alpha]")
        exit(1)

    alpha = " ".join(argv[1:])
    # print(alpha)

    # choose RSA key source 0: From RSA key generator; 1:From saved key_bytes files
    RSA_key_src = 0

    if (RSA_key_src == 0):
        # A) From RSA key generator
        keys_numbers = Crypto_RSA.generate_key_numbers(65537, 2048)
    else:
        # B) From saved key_bytes files
        keys_numbers = get_key_numbers_from_files()

    # use key number to new RSA_PublicKey() and RSA_PrivateKey() instances
    rsa_publickey = RSA_PublicKey(keys_numbers['n'], keys_numbers['e'])
    rsa_privatekey = RSA_PrivateKey(keys_numbers['n'], keys_numbers['d'])

    # print(rsa_publickey.__repr__())
    # print(rsa_privatekey.__repr__())

    # k should be no less than key_size/8
    k = int(keys_numbers['key_size'] / 8)

    # generate proof pi
    pi = RSA_FDH_VRF.prove(rsa_privatekey, alpha, k)
    # print(pi)

    # generate hash value v
    beta = RSA_FDH_VRF.proof2hash(pi)

    print(beta)
    print(RSA_FDH_VRF.os2ip(beta))
    print(RSA_FDH_VRF.i2osp(RSA_FDH_VRF.os2ip(beta), 20))

    print(RSA_FDH_VRF.verifying(rsa_publickey, alpha, pi, k))