import os, binascii, hashlib, base58, ecdsa, random, qrcode

def shex(x):
    return binascii.hexlify(x).decode()

def b58checksum(x):
    checksum = hashlib.sha256(hashlib.sha256(x).digest()).digest()[:4]
    return base58.b58encode(x + checksum)

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

#priv_key = os.urandom(32)
#print(priv_key)

# generate private key

#random.seed(1337)
dat_seed = 602057687353570299698533316470747541848581848175913437975242560153359992341859183495579392720926334317926360144163753509165433777174370375503669893180678037828190108838657560209946521262509792282192887039426181736226204416607422926108649983
for i in range(1, 10):
    dat_seed += 1
    random.seed(dat_seed)
    priv_key = bytes([random.randint(0, 255) for x in range(32)])
    print("privateKey is: {}".format(shex(priv_key)))
    WIF = b58checksum( b'\x80' + priv_key)
    print("WIF is: {}".format(WIF))
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    publ_key = b'\x04' + vk.to_string()
    print("pubkey is: {}".format(shex(publ_key)))
    hash160 = ripemd160(hashlib.sha256(publ_key).digest()).digest()
    publ_addr = b58checksum( b'\x00' + hash160)
    print("publ_addr is: {}".format(publ_addr))
    print()


# make a qrcode corresponding to our pubkey

img = qrcode.make(publ_addr)
img.save("coin.png")
