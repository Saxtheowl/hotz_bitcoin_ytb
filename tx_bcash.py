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
BCASH_SEED = 'seed.bitcoinabc.org'

# tx id:
# b24c3c1be47420e9d55f6fd17fe38757383eb47d0623cf276008ab5ce8887916

# input:
# qrpv3hz5vdf3x0z7xpzx2fpwq05edhzlty999yfvds

# output:
# qze33fur625ewslzst5wp3eehgj96vyy3szq484cq9
# qq7rl4g7j738pxdmrqn5j8z69l2gxycy0vgvay6uxd

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
    return priv_key, WIF, publ_addr

priv_key, WIF, publ_addr = get_key_with_seed()
_, _, publ_addr2 = get_key_with_seed(1338)

dat_secret_seed = read_integer('secret')

_, WIF3, publ_addr3 = get_key_with_seed(dat_secret_seed)
_, WIF4, publ_addr4 = get_key_with_seed(dat_secret_seed + 1337)

def makeMessage(command, payload):
    return struct.pack('<L12sL4s', BCASH_MAGIC, command, len(payload), checksum(payload)) + payload

def getVersionMsg():
    version = 170002
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
    payload = struct.pack('<LBsBsL', version, 1, tx_in, 1, tx_out, locktime)
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
    print(command)
    hexdump(payload)
    return command, payload

if __name__ == "__main__":

    peers = socket.gethostbyname_ex(BCASH_SEED)[2]
    peer = random.choice(peers) # wtf does the return take x time to be random
    print("peer is:{}".format(peer))
    print("we send from %s to %s" % (publ_addr3, publ_addr4))
    
    vermsg = getVersionMsg()
    hexdump(vermsg)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((peer, 8333))
    sock.send(vermsg)
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)

#    genesis_block = binascii.unhexlify('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')[::-1]
    my_block = binascii.unhexlify('000000000000000002ca6e4f04ceeb582b237c118e1df18695ee344bc7919cd2')[::-1]
    
    msg = makeMessage(b'verack', b'')
    sock.send(msg)
    print("send verack")
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)
    cmd, payload = recvMessage(sock)
    
    msg = makeMessage(b'getdata', struct.pack('<BL32s', 1, 2, my_block[::-1]))
    hexdump(msg)
    sock.send(msg)
    cmd, payload = recvMessage(sock)
    txes = payload[4+32+32+4+4+4:]
    hexdump(txes[0:0x100])

    idx = txes.find(binascii.unhexlify('b24c3c1be47420e9d55f6fd17fe38757383eb47d0623cf276008ab5ce8887916'))
    print(idx)
    
#    exit(0)
   
# print("%s -> %s" % (publ_addr, publ_addr2))
# print(publ_addr3)

#print("privateKey is: {}".format(shex(priv_key)))
#print("WIF is: {}".format(WIF3))
#print("pubkey is: {}".format(publ_key))
#print("publ_addr is: {}".format(publ_addr3))
