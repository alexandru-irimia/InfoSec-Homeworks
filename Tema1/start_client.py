from Client import Client

if __name__ == '__main__':
    client = Client(12345, b'OFB')
    client.start()
