from socket import *
from KeyManager import KeyManager
from ECBEncryptionMode import ECBEncryptionMode
from OFBEncryptionMode import OFBEncryptionMode
from Crypto.Cipher import AES


class Server:
    def __init__(self, port: int):
        self.iv = KeyManager.get_iv()
        self.public_key = KeyManager.public_key()
        self.s = socket()
        self.port = port
        self.mode = b''
        self.enc = None

    def start(self):
        self.s.bind(('', self.port))
        self.s.listen(2)

        while True:
            c, _ = self.s.accept()
            self.__communicate(c)
            c.close()

    def __communicate(self, c: socket):
        self.mode = c.recv(3)
        private_key = c.recv(16)

        c.send(b'Start')

        aes = AES.new(self.public_key, AES.MODE_ECB)
        private_key = aes.decrypt(private_key)

        if self.mode == b'ECB':
            self.enc = ECBEncryptionMode(private_key)
        elif self.mode == b'OFB':
            self.enc = OFBEncryptionMode(private_key, self.iv)

        size = int.from_bytes(c.recv(4), 'big')
        text = c.recv(size)
        text = self.enc.decrypt(text)

        print(f"File content = {text}")
