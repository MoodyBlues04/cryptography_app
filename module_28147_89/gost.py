import struct
from typing import List, Union
import os


class Pkcs7:
    def __init__(self, max_pad_len: int) -> None:
        self.__max_pad_len = max_pad_len

    def pad_data(self, data: bytes) -> bytes:
        pad_len = self.__max_pad_len - (len(data) % self.__max_pad_len)
        return data + bytes([pad_len] * pad_len)

    def unpad_data(self, data: bytes) -> bytes:
        pad_len = data[-1]
        self.__validate_pad_len(pad_len)
        return data[:-pad_len]

    def __validate_pad_len(self, pad_len: int) -> None:
        if pad_len > self.__max_pad_len:
            raise ValueError("Некорректное дополнение данных.")


class GostEcb:
    _DEFAULT_S_BOX = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
    ]
    _KEY_SIZE = 32
    _BLOCK_SIZE = 8

    def __init__(self, key: bytes, s_box: List[List[int]] = None) -> None:
        self.__validate_key(key)
        self._key = key
        self._subkeys = struct.unpack('>8L', key)
        self._s_box = s_box or self._DEFAULT_S_BOX
        self.__pkcs7 = Pkcs7(max_pad_len=self._BLOCK_SIZE)

    def encrypt(self, plaintext: Union[bytes, str]) -> bytes:
        plaintext = self._s_to_bytes(plaintext)
        plaintext = self.__pkcs7.pad_data(plaintext)
        encrypted_data = b''
        for i in range(0, len(plaintext), self._BLOCK_SIZE):
            block = int.from_bytes(plaintext[i:i + self._BLOCK_SIZE], 'big')
            encrypted_block = self._encrypt_block(block)
            encrypted_data += encrypted_block.to_bytes(self._BLOCK_SIZE, 'big')
        return encrypted_data

    def decrypt(self, ciphertext: bytes) -> bytes:
        decrypted_data = b''
        for i in range(0, len(ciphertext), self._BLOCK_SIZE):
            block = int.from_bytes(ciphertext[i:i + self._BLOCK_SIZE], 'big')
            decrypted_block = self._decrypt_block(block)
            decrypted_data += decrypted_block.to_bytes(self._BLOCK_SIZE, 'big')
        return self.__pkcs7.unpad_data(decrypted_data)

    def _encrypt_block(self, block: int) -> int:
        left, right = block >> 32, block & 0xFFFFFFFF
        for i in range(32):
            subkey = self._subkeys[self.__get_subkey_idx(i)]
            new_right = left ^ self._f_function(right, subkey)
            left, right = right, new_right
        return (left << 32) | right

    def _decrypt_block(self, block: int) -> int:
        left, right = block >> 32, block & 0xFFFFFFFF
        for i in range(31, -1, -1):
            subkey = self._subkeys[self.__get_subkey_idx(i)]
            new_left = right ^ self._f_function(left, subkey)
            left, right = new_left, left
        return (left << 32) | right

    def _f_function(self, block: int, subkey: int) -> int:
        block = (block + subkey) % 2 ** 32
        output = 0
        for i in range(8):
            s_box_index = (block >> (4 * i)) & 0xF
            output |= self._s_box[i][s_box_index] << (4 * i)
        return ((output << 11) | (output >> (32 - 11))) & 0xFFFFFFFF

    def __get_subkey_idx(self, i: int) -> int:
        return i % self._BLOCK_SIZE if i < 24 else 7 - (i % self._BLOCK_SIZE)

    def __validate_key(self, key: bytes):
        if len(key) != self._KEY_SIZE:
            raise ValueError(f"Ключ должен быть длиной {self._KEY_SIZE} байт.")

    def _s_to_bytes(self, text: Union[str, bytes]) -> bytes:
        return text.encode('utf-8') if isinstance(text, str) else text

    def _xor_bytes(self, bytes_a: bytes, bytes_b: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(bytes_a, bytes_b))


class GostCtr(GostEcb):
    def __init__(self, key: bytes, nonce: bytes = None, s_box: List[List[int]] = None) -> None:
        super().__init__(key, s_box)
        if nonce is None:
            nonce = os.urandom(4)
        self.__validate_nonce(nonce)
        self.__nonce = int.from_bytes(nonce, byteorder='big')

    def encrypt(self, plaintext: Union[bytes, str]) -> bytes:
        plaintext = self._s_to_bytes(plaintext)

        encrypted_data = b''
        for i in range(0, len(plaintext), self._BLOCK_SIZE):
            block = plaintext[i:i + self._BLOCK_SIZE]
            encrypted_data += self._xor_bytes(block, self._gamma(i))
        return encrypted_data

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)

    def _gamma(self, counter: int) -> bytes:
        return self._encrypt_block(self.__nonce + counter).to_bytes(self._BLOCK_SIZE, 'big')

    def __validate_nonce(self, nonce: bytes) -> None:
        if len(nonce) != 4:
            raise ValueError("Nonce должен быть длиной 4 байта.")


class GostCfb(GostEcb):
    def __init__(self, key: bytes, init_vec: bytes = None, s_box: List[List[int]] = None):
        super().__init__(key, s_box)
        init_vec = init_vec if init_vec is not None else os.urandom(self._BLOCK_SIZE)
        self.__ensure_block_len(init_vec)
        self.__init_vec = init_vec

    def encrypt(self, plaintext: Union[bytes, str]) -> bytes:
        plaintext = self._s_to_bytes(plaintext)
        encrypted_data = b''
        prev_block = self.__init_vec
        for i in range(0, len(plaintext), self._BLOCK_SIZE):
            block = plaintext[i:i + self._BLOCK_SIZE]
            encrypted_block = self._xor_bytes(block, self._gamma(prev_block))
            encrypted_data += encrypted_block
            prev_block = encrypted_block
        return encrypted_data

    def decrypt(self, ciphertext: bytes) -> bytes:
        decrypted_data = b''
        prev_block = self.__init_vec
        for i in range(0, len(ciphertext), self._BLOCK_SIZE):
            block = ciphertext[i:i + self._BLOCK_SIZE]
            decrypted_data += self._xor_bytes(block, self._gamma(prev_block))
            prev_block = block
        return decrypted_data

    def _gamma(self, prev_block: bytes) -> bytes:
        return self._encrypt_block(int.from_bytes(prev_block, 'big')).to_bytes(self._BLOCK_SIZE, 'big')

    def __ensure_block_len(self, block: bytes):
        if len(block) != self._BLOCK_SIZE:
            raise ValueError(f"Блок должен быть длиной {self._BLOCK_SIZE} байт.")


def get_algo_class(mode: str):
    ALGO_MODES = {
        'ECB': lambda key: GostEcb(key),
        'CTR': lambda key, nonce: GostCtr(key, nonce),
        'CFB': lambda key, init_vec: GostCfb(key, init_vec)
    }
    return ALGO_MODES.get(mode)


def encrypt(params: dict) -> str:
    cipher = __make_gost(params)
    text = params.get('text')
    if text is None:
        raise Exception('Введите текст для шифрования')
    return cipher.encrypt(text).hex()


def decrypt(params: dict) -> str:
    cipher = __make_gost(params)
    text = params.get('text')
    if text is None:
        raise Exception('Введите текст для дешифровки')
    return cipher.decrypt(bytes.fromhex(text)).decode('utf-8')


def __make_gost(params: dict):
    mode, key = __get_or_fail('mode', params, 'Введите mode'), __get_or_fail('key', params, 'Введите key')
    gost_constructor = get_algo_class(mode)
    if gost_constructor is None:
        raise Exception(f"Некорректный режим работы алгоритма: '{mode}'")

    if mode == 'CTR':
        nonce = __get_or_fail('nonce', params, 'Для режима CTR введите nonce')
        return gost_constructor(key, nonce)
    if mode == 'CFB':
        init_vec = __get_or_fail('init_vec', params, 'Для режима CFB введите init_vec')
        return gost_constructor(key, init_vec)
    return gost_constructor(key)


def __get_or_fail(key: str, params: dict, message: str):
    val = params.get(key)
    if val is None:
        raise Exception(message)
    return val


if __name__ == "__main__":
    _key = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    _plaintext = "Hello, ГОСТ 28147-89!"

    init_vec = os.urandom(8)
    encrypted = encrypt({'mode': 'CFB', 'text': _plaintext, 'key': _key, 'init_vec': init_vec})
    print(encrypted, decrypt({'mode': 'CFB', 'text': encrypted, 'key': _key, 'init_vec': init_vec}))
