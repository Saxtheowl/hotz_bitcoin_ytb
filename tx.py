import os, binascii, hashlib, base58, ecdsa, random, qrcode

# QR CODE

# import qrcode
# img = qrcode.make(publ_addr)
# img.save("coin.png")

def shex(x):
    return binascii.hexlify(x).decode()

def b58checksum(x):
    checksum = hashlib.sha256(hashlib.sha256(x).digest()).digest()[:4]
    return base58.b58encode(x + checksum)

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
#print("privateKey is: {}".format(shex(priv_key)))
#print("WIF is: {}".format(WIF))
#print("pubkey is: {}".format(publ_key))
#print("publ_addr is: {}".format(publ_addr, publ_addr2))
print("%s -> %s" % (publ_addr, publ_addr2))
