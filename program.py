import hashlib
from Crypto.Hash import MD5, SHA256, SHA
from Crypto.Cipher import AES, PKCS1_OAEP, DES3
from Crypto.PublicKey import RSA, DSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss, DSS
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from time import time
import base64
from Crypto.Cipher import ARC4

###
#PYTHON VERSION 2.7.6
#sudo pip install pycryptodome
#python program.py
###
def MD5e(messages):
    print("Generating MD5 times")
    h = MD5.new()
    times = list()
    n = 500000
    for msg in messages:
        acum_time = 0
        for _ in range(n):
            t_start = time()
            h.update(msg)
            t_end = time()
            total_time = t_end - t_start
            acum_time += total_time
        final_time = acum_time / n
        times.append(final_time)
    return times


def SHA1e(messages):
    print("Generating SHA1 Times")
    h = SHA.new()
    times = list()
    n = 500000
    for msg in messages:
        acum_time = 0
        for _ in range(n):
            t_start = time()
            h.update(msg)
            t_end = time()
            total_time = t_end - t_start
            acum_time += total_time
        final_time = acum_time / n
        times.append(final_time)
    return times
    

def SHA256e(messages):
    print("Generating SHA256 Times")
    times = list()
    h = SHA256.new()
    n = 500000
    for msg in messages:
        acum_time = 0
        for _ in range(n):
            t_start = time()
            h.update(msg)
            t_end = time()
            total_time = t_end - t_start
            acum_time += total_time
        final_time = acum_time / n
        times.append(final_time)
    return times


def AESe(k, messages):
    print("Generating AES Times")
    times = list()
    for msg in messages:
        t_start = time()
        key = str.encode(k[0:32])
        cipher = AES.new(key, AES.MODE_EAX)
        cipher_text=cipher.encrypt(str.encode(msg))
        t_end = time()
        total_time = t_end - t_start
        times.append(total_time)
    return times
    
    
def DESe(k, messages):
    print("Generating DES Times")
    times = list()
    for msg in messages:
        t_start = time()
        key = str.encode(k[0:16])
        DES3.adjust_key_parity(key)
        cipher = DES3.new(key, DES3.MODE_EAX)
        cipher_text = cipher.nonce + cipher.encrypt(str.encode(msg))
        t_end = time()
        total_time = t_end - t_start
        times.append(total_time)
    return times


def RSAOEAPe():
    print("Generating RSAOAEP Times")
    f=open("RSAOEAP.txt","r")
    times = list()
    for x in range(10):
        t_start = time()
        tupkey=(int(f.readline(),16),int(f.readline(),16),int(f.readline(),16),int(f.readline(),16),int(f.readline(),16))
        key = RSA.construct(tupkey)
        cipher_rsa = PKCS1_OAEP.new(key)
        a=cipher_rsa.encrypt(b'RSAOEAP')
        t_final = time()
        total_time = t_final - t_start
        times.append(total_time)
    return times
    
    
def RSAPSSe():
    print("Generating RSAPSS Times")
    f=open("RSAOEAP.txt","r")
    message = '0000000000000000000000000000000000000000'
    times = list()
    for x in range(10):
        t_start = time()
        tupkey = (int(f.readline(),16),int(f.readline(),16),int(f.readline(),16),int(f.readline(),16),int(f.readline(),16))
        key = RSA.construct(tupkey)
        h = SHA256.new(message)
        signature = pss.new(key).sign(h)
        verifier = pss.new(key)
        t_final = time()
        total_time = t_final - t_start
        times.append(total_time)
    return times      
    
    
def DSAe():
    print("Generating DSA Times")
    f=open("DSA.txt","r")
    times = list()
    for x in range(10):
        t_start = time()
        tupkey=(int (f.readline(),16),int (f.readline(),16),int (f.readline(),16),int(f.readline(),16),int(f.readline(),16))
        key = DSA.construct(tupkey)
        h = SHA256.new(str.encode(f.readline()))
        signer = DSS.new(key, 'fips-186-3')
        a=signer.sign(h)
        t_final = time() 
        total_time = t_final - t_start
        times.append(total_time)
    return times
    

def ARC4e(key, message):
    sha = SHA.new()
    sha.update(key)
    rc4_key = sha.digest()

    rc4 = ARC4.new(rc4_key)
    encrypted = rc4.encrypt(message)
    
    return encrypted
    
def ARC4m(k, messages):
    print("Generating ARC4 Times")
    key = bytearray.fromhex(k)
    times = list()
    n = 5000
    for msg in messages:
        acum_time = 0
        for _ in range(n):
            t_start = time()
            ARC4e(key, msg)
            t_end = time()
            total_time = t_end - t_start
            acum_time += total_time
        final_time = acum_time / n
        times.append(final_time)
    return times
    
    
def write_hash_times(md5, sha1, sha256):
    with open('hash_times.txt', 'w') as file:
        print>> file, '\nMD5 times\n'
        print>> file, md5
        print>> file, '\nSHA1 times\n'
        print>> file, sha1
        print>> file, '\nSHA256 times\n'
        print>> file, sha256

def write_signature_times(PSSr, DSAr): 
    with open('signatures_times.txt', 'w') as file:
        print>> file, '\nRSA-PSS times\n'
        print>> file, PSSr
        print>> file, '\nDSA times\n'
        print>> file, DSAr
        
def write_encrypt_times(des, aes, rsaoeap, ARC4m): 
    with open('encrypt_times.txt', 'w') as file:
        print>> file, '\nDES times\n'
        print>> file, des
        print>> file, '\nAES times\n'
        print>> file, aes
        print>> file, '\nRSA-OEAP times\n'
        print>> file, rsaoeap
        print>> file, '\nARC4 times\n'
        print>> file, ARC4m
    
def main():
    messages = ['','a','ab','abc','message digest','abcdefghijklmnopqrstuvwxyz','abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq','ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',8*'1234567890',1000*'a']
    key = 'thisisthekey10293_lasdlladj1293230a_lasjdlkasjd941487239874923'
    keyArc = '80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
    #HASHING ALGORITHMS
    """
    md5_times = MD5e(messages)
    sha1_times = SHA1e(messages)
    sha256_times = SHA256e(messages)
    write_hash_times(md5_times, sha1_times, sha256_times)
    #ENCRYPTING ALGORITHMS
    """
    
    #SIGNATURES
    '''
    pss = RSAPSSe()
    dsa = DSAe()
    write_signature_times(pss, dsa)
    aes_times = AESe('8000000000000000000000000000000000000000000000000000000000000000', messages)
    des_times = DESe('8000000000000000000000000000000000000000000000000000000000000000', messages)
    roeap = RSAOEAPe()
    print roeap
    '''
    """
    #Encrypt
    des = DESe(keyArc, messages)#key y message
    aes = AESe(keyArc, messages) #key y message
    rsauaep = RSAOEAPe() #nada
    arc4 = ARC4m(keyArc, messages) #key y message
    write_encrypt_times(des,aes,rsauaep,arc4)
    """
main()

