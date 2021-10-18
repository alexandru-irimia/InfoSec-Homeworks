from EncryptionMode import EncryptionMode
from Crypto.Cipher import AES


class ECBEncryptionMode(EncryptionMode):
    def __init__(self, key: bytes):
        self.key = key

    def decrypt(self, ciphertext: bytes):
        blocks = ECBEncryptionMode.__divide_in_blocks(ciphertext)
        plaintext = b''

        aes = AES.new(self.key, AES.MODE_ECB)

        for block in blocks:
            plaintext += aes.decrypt(block)

        return EncryptionMode.del_padding(plaintext)

    def encrypt(self, plaintext: bytes):
        plaintext = EncryptionMode.add_padding(plaintext)
        blocks = ECBEncryptionMode.__divide_in_blocks(plaintext)

        aes = AES.new(self.key, AES.MODE_ECB)
        ciphertext = b''

        for block in blocks:
            encrypted_block = aes.encrypt(block)
            ciphertext += encrypted_block

        return ciphertext

    @staticmethod
    def __divide_in_blocks(text: bytes):
        blocks = []

        for i in range(0, len(text), 16):
            blocks.append(text[i:i + 16])

        return blocks
