from socket import *
from KeyManager import KeyManager
from ECBEncryptionMode import ECBEncryptionMode
from OFBEncryptionMode import OFBEncryptionMode
from Crypto.Cipher import AES


class Client:
    def __init__(self, port: int, mode: bytes = b'ECB'):
        self.iv = KeyManager.get_iv()
        self.public_key = KeyManager.public_key()
        self.s = socket()
        self.port = port
        self.mode = mode
        self.enc = None

    def start(self):
        self.s.connect(('127.0.0.1', self.port))
        self.__communicate()
        self.s.close()

    def __communicate(self):
        private_key = KeyManager.private_key()
        self.s.send(self.mode + private_key)

        aes = AES.new(self.public_key, AES.MODE_ECB)
        private_key = aes.decrypt(private_key)

        if self.mode == b'ECB':
            self.enc = ECBEncryptionMode(private_key)
        elif self.mode == b'OFB':
            self.enc = OFBEncryptionMode(private_key, self.iv)

        begin = self.s.recv(5)

        if begin != b'Start':
            return

        file = input("File : ")

        f = open(file, 'rb')
        content = f.read()

        content = self.enc.encrypt(content)
        size = len(content).to_bytes(4, 'big')

        self.s.send(size+content)
