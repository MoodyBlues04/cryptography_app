import struct
from typing import List, Union
import os


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')


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


class GostSteps:
    """
        result: res,
        blocks: [
            {
                block: 0,
                result: 0,
                rounds: [],
            },
        ]
    """

    def __init__(self):
        self.__blocks = []

    def add_block(self, block: int) -> None:
        self.__blocks.append({'block': self.__int_to_str(block), 'rounds': [], 'result': None})

    def add_block_res(self, res: int, block_idx=-1) -> None:
        self.__blocks[block_idx]['result'] = self.__int_to_str(res)

    def add_block_round(self, round: int, block_idx=-1) -> None:
        self.__blocks[block_idx]['rounds'].append((round >> 32, round & 0xFFFFFFFF))

    def get_steps(self) -> list:
        return self.__blocks

    def __int_to_str(self, val: int) -> str:
        return self.__decode_bytes_safe(val.to_bytes(8, byteorder='big'))

    def __decode_bytes_safe(self, bytes_str: bytes) -> str:
        result = ''
        for byte in bytes_str:
            try:
                result += bytes([byte]).decode('utf-8')
            except UnicodeDecodeError:
                result += f'\\x{byte:02x}'
        return result


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
    _ROUNDS_COUNT = 32
    _KEY_SIZE = 32
    _BLOCK_SIZE = 8

    def __init__(self, key: bytes, s_box: List[List[int]] = None) -> None:
        self.__validate_key(key)
        self._key = key
        self._subkeys = struct.unpack('>8L', key)
        self._s_box = s_box or self._DEFAULT_S_BOX
        self.__pkcs7 = Pkcs7(max_pad_len=self._BLOCK_SIZE)
        self._steps = GostSteps()

    def get_steps(self) -> list:
        return self._steps.get_steps()

    def encrypt(self, plaintext: Union[bytes, str]) -> bytes:
        self._steps = GostSteps()
        plaintext = self.s_to_bytes(plaintext)
        plaintext = self.__pkcs7.pad_data(plaintext)
        encrypted_data = b''
        for i in range(0, len(plaintext), self._BLOCK_SIZE):
            block = _bytes_to_int(plaintext[i:i + self._BLOCK_SIZE])
            self._steps.add_block(block)
            encrypted_block = self._encrypt_block(block)
            self._steps.add_block_res(encrypted_block)
            encrypted_data += encrypted_block.to_bytes(self._BLOCK_SIZE, 'big')
        return encrypted_data

    def decrypt(self, ciphertext: bytes) -> bytes:
        self._steps = GostSteps()
        decrypted_data = b''
        for i in range(0, len(ciphertext), self._BLOCK_SIZE):
            block = _bytes_to_int(ciphertext[i:i + self._BLOCK_SIZE])
            self._steps.add_block(block)
            decrypted_block = self._decrypt_block(block)
            self._steps.add_block_res(decrypted_block)
            decrypted_data += decrypted_block.to_bytes(self._BLOCK_SIZE, 'big')
        return self.__pkcs7.unpad_data(decrypted_data)

    def _encrypt_block(self, block: int) -> int:
        left, right = block >> 32, block & 0xFFFFFFFF
        for i in range(self._ROUNDS_COUNT):
            subkey = self._subkeys[self.__get_subkey_idx(i)]
            new_right = left ^ self._f_function(right, subkey)
            left, right = right, new_right
            self._steps.add_block_round(self.__join_ints(left, right))
        return self.__join_ints(left, right)

    def _decrypt_block(self, block: int) -> int:
        left, right = block >> 32, block & 0xFFFFFFFF
        for i in range(self._ROUNDS_COUNT - 1, -1, -1):
            subkey = self._subkeys[self.__get_subkey_idx(i)]
            new_left = right ^ self._f_function(left, subkey)
            left, right = new_left, left
            self._steps.add_block_round(self.__join_ints(left, right))
        return self.__join_ints(left, right)

    def __join_ints(self, left: int, right: int):
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

    @staticmethod
    def s_to_bytes(text: Union[str, bytes]) -> bytes:
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
        plaintext = self.s_to_bytes(plaintext)

        encrypted_data = b''
        for i in range(0, len(plaintext), self._BLOCK_SIZE):
            block = plaintext[i:i + self._BLOCK_SIZE]
            self._steps.add_block(_bytes_to_int(block))
            encrypted_block = self._xor_bytes(block, self._gamma(i))
            self._steps.add_block_res(_bytes_to_int(encrypted_block))
            encrypted_data += encrypted_block
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
        plaintext = self.s_to_bytes(plaintext)
        encrypted_data = b''
        prev_block = self.__init_vec
        for i in range(0, len(plaintext), self._BLOCK_SIZE):
            block = plaintext[i:i + self._BLOCK_SIZE]
            self._steps.add_block(_bytes_to_int(block))
            encrypted_block = self._xor_bytes(block, self._gamma(prev_block))
            self._steps.add_block_res(_bytes_to_int(encrypted_block))
            encrypted_data += encrypted_block
            prev_block = encrypted_block
        return encrypted_data

    def decrypt(self, ciphertext: bytes) -> bytes:
        decrypted_data = b''
        prev_block = self.__init_vec
        for i in range(0, len(ciphertext), self._BLOCK_SIZE):
            block = ciphertext[i:i + self._BLOCK_SIZE]
            self._steps.add_block(_bytes_to_int(block))
            decrypted_block = self._xor_bytes(block, self._gamma(prev_block))
            self._steps.add_block_res(_bytes_to_int(decrypted_block))
            decrypted_data += decrypted_block
            prev_block = block
        return decrypted_data

    def _gamma(self, prev_block: bytes) -> bytes:
        return self._encrypt_block(_bytes_to_int(prev_block)).to_bytes(self._BLOCK_SIZE, 'big')

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


def encrypt(params: dict) -> dict:
    cipher = __make_gost(params)
    text = params.get('text')
    if text is None:
        raise Exception('Введите текст для шифрования')
    return {
        'result': cipher.encrypt(text).hex(),
        'steps': cipher.get_steps()
    }


def decrypt(params: dict) -> dict:
    cipher = __make_gost(params)
    text = params.get('text')
    if text is None:
        raise Exception('Введите текст для дешифровки')
    return {
        'result': cipher.decrypt(bytes.fromhex(text)).decode('utf-8'),
        'steps': cipher.get_steps()
    }


def __make_gost(params: dict):
    mode, key = __get_or_fail('mode', params, 'Введите mode'), __get_or_fail('key', params, 'Введите key')
    key = GostEcb.s_to_bytes(key)

    gost_constructor = get_algo_class(mode)
    if gost_constructor is None:
        raise Exception(f"Некорректный режим работы алгоритма: '{mode}'")

    if mode == 'CTR':
        nonce = __get_or_fail('nonce', params, 'Для режима CTR введите nonce')
        return gost_constructor(key, GostEcb.s_to_bytes(nonce))
    if mode == 'CFB':
        init_vec = __get_or_fail('init_vec', params, 'Для режима CFB введите init_vec')
        return gost_constructor(key, GostEcb.s_to_bytes(init_vec))
    return gost_constructor(key)


def __get_or_fail(key: str, params: dict, message: str):
    val = params.get(key)
    if val is None:
        raise Exception(message)
    return val
