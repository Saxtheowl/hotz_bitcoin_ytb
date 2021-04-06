import random, os

# print(priv_key)
random.seed(1337)
#priv_key = bytes([random.randint(0, 255) for x in range(32)])

priv_key_list = []
for x in range(32):
    priv_key_list.append(random.randint(0, 255))

#priv_key = bytes(priv_key_list)
priv_key = priv_key_list
print(priv_key)
