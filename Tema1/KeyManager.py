from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


class KeyManager:
    @staticmethod
    def get_iv():
        return b'\x01\x02\x03\x04\xca\xfe\xba\xbe\x04\x03\x02\x01\xca\xfe\xba\xbe'

    @staticmethod
    def public_key():
        return b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

    @staticmethod
    def private_key():
        key = get_random_bytes(16)

        aes = AES.new(KeyManager.public_key(), AES.MODE_ECB)
        enc = aes.encrypt(key)

        return enc
