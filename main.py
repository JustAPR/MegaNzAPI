from fastapi import FastAPI
from typing import List
import base64
import struct
import hashlib
import codecs
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import math
from pydantic import BaseModel
def aes_cbc_encrypt(data, key):
    aes_cipher = AES.new(key, AES.MODE_CBC, makebyte('\0' * 16))
    return aes_cipher.encrypt(data)
def aes_cbc_decrypt(data, key):
    aes_cipher = AES.new(key, AES.MODE_CBC, makebyte('\0' * 16))
    return aes_cipher.decrypt(data)
def aes_cbc_encrypt_a32(data, key):
    return str_to_a32(aes_cbc_encrypt(a32_to_str(data), a32_to_str(key)))
def aes_cbc_decrypt_a32(data, key):
    return str_to_a32(aes_cbc_decrypt(a32_to_str(data), a32_to_str(key)))
def encrypt_key(a, key):
    return sum((aes_cbc_encrypt_a32(a[i:i + 4], key)
                for i in range(0, len(a), 4)), ())
def decrypt_key(a, key):
    return sum((aes_cbc_decrypt_a32(a[i:i + 4], key)
                for i in range(0, len(a), 4)), ())
def makebyte(x):
    return codecs.latin_1_encode(x)[0]
def makestring(x):
    return codecs.latin_1_decode(x)[0]
def a32_to_str(a):
    return struct.pack('>%dI' % len(a), *a)
def str_to_a32(b):
    if isinstance(b, str):
        b = makebyte(b)
    if len(b) % 4:
        b += b'\0' * (4 - len(b) % 4)
    return struct.unpack('>%dI' % (len(b) / 4), b)
def base64_url_decode(data):
    data += '=='[(2 - len(data) * 3) % 4:]
    for search, replace in (('-', '+'), ('_', '/'), (',', '')):
        data = data.replace(search, replace)
    return base64.b64decode(data)
def base64_to_a32(s):
    return str_to_a32(base64_url_decode(s))
def base64_url_encode(data):
    data = base64.b64encode(data)
    data = makestring(data)
    for search, replace in (('+', '-'), ('/', '_'), ('=', '')):
        data = data.replace(search, replace)
    return data
def a32_to_base64(a):
    return base64_url_encode(a32_to_str(a))
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)
def modular_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m   
def mpi_to_int(s):
    return int(binascii.hexlify(s[2:]), 16)

app = FastAPI()

@app.get('/')
async def ha(salt: str,pa: str):
    pbkdf2_key = hashlib.pbkdf2_hmac(hash_name='sha512', password=pa.encode(), salt=a32_to_str(
        base64_to_a32(salt)), iterations=100000, dklen=32)
    password_aes = str_to_a32(pbkdf2_key[:16])
    user_hash = base64_url_encode(pbkdf2_key[-16:])
    return {"s":user_hash,"p":password_aes}

class InputData(BaseModel):
    k: str
    pk: str
    csid: str
    password: List[int]

@app.post("/logins/")
async def logins_endpoint(data: InputData):
    k = data.k
    pk = data.pk
    csid = data.csid
    password = data.password
    encrypted_master_key = base64_to_a32(k)
    master_key = decrypt_key(encrypted_master_key, password)
    encrypted_rsa_private_key = base64_to_a32(pk)
    rsa_private_key = decrypt_key(encrypted_rsa_private_key,
                                          master_key)
    private_key = a32_to_str(rsa_private_key)
    rsa_private_key = [0, 0, 0, 0]
    for i in range(4):
                bitlength = (private_key[0] * 256) + private_key[1]
                bytelength = math.ceil(bitlength / 8)
                bytelength += 2
                rsa_private_key[i] = mpi_to_int(private_key[:bytelength])
                private_key = private_key[bytelength:]

    first_factor_p = rsa_private_key[0]
    second_factor_q = rsa_private_key[1]
    private_exponent_d = rsa_private_key[2]
    rsa_modulus_n = first_factor_p * second_factor_q
    phi = (first_factor_p - 1) * (second_factor_q - 1)
    public_exponent_e = modular_inverse(private_exponent_d, phi)

    rsa_components = (
                rsa_modulus_n,
                public_exponent_e,
                private_exponent_d,
                first_factor_p,
                second_factor_q,
            )
    rsa_decrypter = RSA.construct(rsa_components)

    encrypted_sid = mpi_to_int(base64_url_decode(csid))

    sid = '%x' % rsa_decrypter._decrypt(encrypted_sid)
    sid = binascii.unhexlify('0' + sid if len(sid) % 2 else sid)
    sid = base64_url_encode(sid[:43])
    return {"sid": sid}