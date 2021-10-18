from abc import ABC, abstractmethod


class EncryptionMode(ABC):
    @abstractmethod
    def encrypt(self, plaintext: bytes):
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes):
        pass

    @staticmethod
    def add_padding(text: bytes):
        padding = 16 - (len(text) % 16)
        text += padding.to_bytes(1, 'big') * padding

        return text

    @staticmethod
    def del_padding(text: bytes):
        padding = text[-1]

        return text[:-padding]
