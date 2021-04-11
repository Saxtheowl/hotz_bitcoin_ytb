import os, binascii, hashlib, base58, ecdsa
import random
import socket
import struct
import time
from hexdump import hexdump

#aimport qrcode
# img = qrcode.make(publ_addr)
# img.save("coin.png")

BITCOIN_MAGIC = 0xd9b4bef9
BITCOIN_SEED = 'dnsseed.bluematt.me'
BCASH_MAGIC = 0xe8f3e1e3
BCASH_SEED = 'seeder.fabien.cash'

# tx id:
# b24c3c1be47420e9d55f6fd17fe38757383eb47d0623cf276008ab5ce8887916

# input:
# qrpv3hz5vdf3x0z7xpzx2fpwq05edhzlty999yfvds

# output:
# qze33fur625ewslzst5wp3eehgj96vyy3szq484cq9
# qq7rl4g7j738pxdmrqn5j8z69l2gxycy0vgvay6uxd

def shex(x):
#    print("hexlify = %s decode = %s" % ( binascii.hexlify(x),  binascii.hexlify(x).decode()))
    return binascii.hexlify(x)

def checksum(x):
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()[:4]

def b58checksum(x):
    return base58.b58encode(x + checksum(x))

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

def read_integer(filename):
    with open(filename) as f:
        return int(f.read())

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
    return priv_key, WIF, hash160, publ_addr

priv_key, WIF, hash1601, publ_addr = get_key_with_seed()
_, _, _, publ_addr2 = get_key_with_seed(1338)

dat_secret_seed = read_integer('secret')

_, WIF3, hash1603, publ_addr3 = get_key_with_seed(dat_secret_seed)
_, WIF4, hash1604, publ_addr4 = get_key_with_seed(dat_secret_seed + 1337)

def makeMessage(command, payload):
    return struct.pack('<L12sL4s', BCASH_MAGIC, command, len(payload), checksum(payload)) + payload

def getVersionMsg():
    version = 180002
    services = 1
    timestamp = int(time.time())
    addr_me = b"\x00" * 26
    addr_you = b"\x00" * 26
    nonce = random.getrandbits(64)
    sub_version_num = b'\x00'

    start_height = 0

    payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_me, addr_you, nonce, sub_version_num, start_height)
    return makeMessage(b'version', payload)

def getTxMsg(tx_in, tx_out):
    version = 1
    locktime = 0
    payload = struct.pack('<LB', version, 1) + tx_in + b'\x01' + tx_out + struct.pack('<L', locktime)
    return makeMessage(b'tx', payload)

def sock_read(sock, count):
    ret = b''
    while len(ret) < count:
        ret += sock.recv(count-len(ret))
    return ret

def recvMessage(sock):
    magic, command, plen, cksum = struct.unpack('<L12sL4s', sock_read(sock, 24))
    assert magic == BCASH_MAGIC
    payload = sock_read(sock, plen)
    assert checksum(payload) == cksum
    if len(payload) > 0x10:
        print("%s %d" % (command, len(payload)))
    else:
        print(command)
        hexdump(payload)
    return command, payload

if __name__ == "__main__":

    peers = socket.gethostbyname_ex(BCASH_SEED)[2]
    peer = random.choice(peers) # wtf does the return take x time to be random
    print("peer is:{}".format(peer))
    print("hash160 shex is %s" % (shex(hash1601)))
    print("we send from %s to %s" % (publ_addr, publ_addr2))
#    exit(0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((peer, 8333))
    sock.send(getVersionMsg())
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)
    print("send verack")
    msg = makeMessage(b'verack', b'')
    sock.send(msg)
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)

#    genesis_block = binascii.unhexlify('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
    my_block = binascii.unhexlify('000000000000000002ca6e4f04ceeb582b237c118e1df18695ee344bc7919cd2')
    his_block = binascii.unhexlify('000000000000000001b9d2f1286800f49908901f6d2259d5c09f0ba7716a53b6')
    msg = makeMessage(b'getdata', struct.pack('<BL32s', 1, 2, his_block[::-1]))
    sock.send(msg)
    
    cmd, payload = recvMessage(sock)
    idx = payload.find(hash1601)
    print(idx)
    hexdump(payload[idx-100:idx+0x100])
    
#    exit(0)
   
# print("%s -> %s" % (publ_addr, publ_addr2))
# print(publ_addr3)

#print("privateKey is: {}".format(shex(priv_key)))
#print("WIF is: {}".format(WIF3))
#print("pubkey is: {}".format(publ_key))
#print("publ_addr is: {}".format(publ_addr3))
