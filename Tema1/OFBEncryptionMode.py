from EncryptionMode import EncryptionMode
from Crypto.Cipher import AES


class OFBEncryptionMode(EncryptionMode):
    def __init__(self, key: bytes, iv: bytes):
        self.key = key
        self.iv = iv

    def decrypt(self, ciphertext: bytes):
        blocks = OFBEncryptionMode.__divide_in_blocks(ciphertext)
        plaintext = b''
        to_encrypt = self.iv

        aes = AES.new(self.key, AES.MODE_ECB)

        for block in blocks:
            encrypted = aes.encrypt(to_encrypt)
            to_encrypt = encrypted
            encrypted = OFBEncryptionMode.xor(encrypted, block)
            plaintext += encrypted

        return EncryptionMode.del_padding(plaintext)

    def encrypt(self, plaintext: bytes):
        plaintext = EncryptionMode.add_padding(plaintext)
        blocks = OFBEncryptionMode.__divide_in_blocks(plaintext)

        aes = AES.new(self.key, AES.MODE_ECB)
        ciphertext = b''
        to_encrypt = self.iv

        for block in blocks:
            encrypted = aes.encrypt(to_encrypt)
            to_encrypt = encrypted
            encrypted = OFBEncryptionMode.xor(encrypted, block)
            ciphertext += encrypted

        return ciphertext

    @staticmethod
    def __divide_in_blocks(text: bytes):
        blocks = []

        for i in range(0, len(text), 16):
            blocks.append(text[i:i + 16])

        return blocks

    @staticmethod
    def xor(x: bytes, y: bytes):
        result = b''

        for i in range(0, len(x)):
            result += (x[i] ^ y[i]).to_bytes(1, 'big')

        return result
