import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import sys

def main():
    password = getpass()
    password = bytearray(password, 'utf-8')
    filename = sys.argv[2]
    if sys.argv[1] in ["-e", "-E"]:
        encrypt(filename, password)
    elif sys.argv[1] in ["-d", "-D"]:
        decrypt(filename, password)


def encrypt(filename, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\xe2\xaf\xbc:\xdd',
        iterations=480000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    k = Fernet(key)

    file = open(filename, "rb")
    text = file.read()
    file.close()
    f2 = open(filename + '_encrypted',"wb")
    f2.write(k.encrypt(text))
    f2.close()


def decrypt(filename, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\xe2\xaf\xbc:\xdd',
        iterations=480000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    k = Fernet(key)

    file = open(filename, "rb")
    text = file.read()
    file.close()
    f2 = open(filename+'_decrypted', "wb")
    f2.write(k.decrypt(text))
    f2.close()


if __name__ == "__main__":
    main()