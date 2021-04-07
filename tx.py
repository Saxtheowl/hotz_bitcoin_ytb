import os, binascii, hashlib, base58, ecdsa
import random
import socket
import struct
import time

# import qrcode
# img = qrcode.make(publ_addr)
# img.save("coin.png")

def shex(x):
    return binascii.hexlify(x).decode()

def checksum(x):
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()[:4]

def b58checksum(x):
    return base58.b58encode(x + checksum(x))

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

def get_key_with_seed(seed = 1337):
#generate_private key
    random.seed(seed)
    priv_list_key = []
    for x in range(32):
        priv_list_key.append(random.randint(0, 255))
        
    priv_key = bytes(priv_list_key)
    # private key -> WIF
    WIF = b58checksum(b'\x80' + priv_key)
    # get public key
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    publ_key = b'\x04' + vk.to_string()
    hash160 = ripemd160(hashlib.sha256(publ_key).digest()).digest()
    publ_addr = b58checksum( b'\x00' + hash160)
    return priv_key, WIF, publ_addr

priv_key, WIF, publ_addr = get_key_with_seed(1337)
_, _, publ_addr2 = get_key_with_seed(1338)
_, _, publ_addr3 = get_key_with_seed(6020576873535702996985333164707475418485818481759134379752425601533599923418591834955793927209263343179263601441637535091654337771743703275503669893180678037828190108838657560209946521262509792282192887039426181736226204416607422926108649983)

magic = 0xe8f3e1e3

def makeMessage(magic, command, payload):
#    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    return struct.pack('L12sL4s', magic, command, len(payload), checksum(payload)) + payload

def getVersionMsg():
    version = 60002
    services = 1
    timestamp = int(time.time())
    addr_me = b"\x00" * 26
    addr_you = b"\x00" * 26
    nonce = random.getrandbits(64)
    sub_version_num = '\x00'

    start_height = 0

    payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_me,
        addr_you, nonce, sub_version_num, start_height)
    return makeMessage(magic, 'version', payload)

if __name__ == "__main__":
    peers = socket.gethostbyname_ex('seed.bitcoinabc.org')[2]
    peer = random.choice(peers) # wtf does the return take x time to be random
    print(peer)
    
    exit(0)
    
    print("%s -> %s" % (publ_addr, publ_addr2))
    print(publ_addr3)

#print("privateKey is: {}".format(shex(priv_key)))
#print("WIF is: {}".format(WIF))
#print("pubkey is: {}".format(publ_key))
#print("publ_addr is: {}".format(publ_addr, publ_addr2))
#QR code
