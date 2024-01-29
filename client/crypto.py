from os import path
from nacl.public import PrivateKey, SealedBox


def parseByteArray(data: bytes) -> list[bytes]:
    begin_delimiter = b"---BEGIN---"
    end_delimiter = b"---END---"

    output = []

    start_index = 0
    while True:
        start_index = data.find(begin_delimiter, start_index)
        if start_index == -1:
            break
        end_index = data.find(end_delimiter, start_index)
        if end_index == -1:
            break

        start_index += len(begin_delimiter)
        output.append(data[start_index:end_index])
        start_index = end_index + len(end_delimiter)

    return output


class Crypto:
    def __init__(self) -> None:
        with open(path.join(path.dirname(__file__), "..", "private.key"), "rb") as f:
            self.secretKey = f.read()

    def decryptFile(self, data: bytes, isFile=False):
        unseal_box = SealedBox(PrivateKey(self.secretKey))

        ciphertexts = parseByteArray(data)

        cleartexts = []

        for cipher in ciphertexts:
            if isFile:
                plaintext = unseal_box.decrypt(cipher)
            else:
                plaintext = unseal_box.decrypt(cipher).decode("utf16")
                print(plaintext)

            cleartexts.append(plaintext)

        return cleartexts
