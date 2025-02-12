class AesGlobals:
    SBOX = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )
    
    INV_SBOX = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )
    
    RCON = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1b000000, 0x36000000
    ]
    
    NB = 4  # Number of columns in the state matrix (also number of words)
    NK = 4  # Number of 32-bit words in the key (4 for AES-128)
    NR = 10  # Number of rounds for AES-128
    NR_ROWS = 4  # Number of rows

    BLOCK_SIZE = 16


class Pkcs7:
    @classmethod
    def pad(cls, data, block_size):
        padding_len = block_size - (len(data) % block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    @classmethod
    def unpad(cls, data):
        padding_len = data[-1]
        if padding_len == 0:
            raise ValueError(f"Invalid padding: {padding_len}, NB: {AesGlobals.NB}")
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid padding")
        return data[:-padding_len]


class AES:
    @classmethod
    def aes_encrypt(cls, plaintext, key):
        cls.__check_block_size(key)

        padded_plaintext = Pkcs7.pad(plaintext, AesGlobals.BLOCK_SIZE)
        ciphertext = b''

        for i in range(0, len(padded_plaintext), AesGlobals.BLOCK_SIZE):
            block = padded_plaintext[i:i + AesGlobals.BLOCK_SIZE]
            ciphertext += cls.aes_encrypt_block(block, key)

        return ciphertext

    @classmethod
    def aes_encrypt_block(cls, plaintext, key):
        state = cls.__bytes2mat(plaintext)

        w = cls.__key_expansion(key)

        cls.__add_round_key(state, w[:AesGlobals.NB])

        for round_num in range(1, AesGlobals.NR):
            cls.__sub_bytes(state)
            cls.__shift_rows(state)
            cls.__mix_columns(state)
            cls.__add_round_key(state, w[round_num * AesGlobals.NB:(round_num + 1) * AesGlobals.NB])

        cls.__sub_bytes(state)
        cls.__shift_rows(state)
        cls.__add_round_key(state, w[AesGlobals.NR * AesGlobals.NB: (AesGlobals.NR + 1) * AesGlobals.NB])

        return cls.__mat2bytes(state)

    @classmethod
    def aes_decrypt(cls, ciphertext, key):
        cls.__check_block_size(key)

        plaintext = b''
        for i in range(0, len(ciphertext), AesGlobals.BLOCK_SIZE):
            block = ciphertext[i:i + AesGlobals.BLOCK_SIZE]
            plaintext += cls.__aes_decrypt_block(block, key)

        return Pkcs7.unpad(plaintext)

    @classmethod
    def __aes_decrypt_block(cls, ciphertext, key):
        state = cls.__bytes2mat(ciphertext)

        w = cls.__key_expansion(key)

        cls.__add_round_key(state, w[AesGlobals.NR * AesGlobals.NB: (AesGlobals.NR + 1) * AesGlobals.NB])

        for round_num in range(AesGlobals.NR - 1, 0, -1):
            cls.__inv_shift_rows(state)
            cls.__inv_sub_bytes(state)
            cls.__add_round_key(state, w[round_num * AesGlobals.NB:(round_num + 1) * AesGlobals.NB])
            cls.__inv_mix_columns(state)

        cls.__inv_shift_rows(state)
        cls.__inv_sub_bytes(state)
        cls.__add_round_key(state, w[0:AesGlobals.NB])

        return cls.__mat2bytes(state)

    @classmethod
    def __key_expansion(cls, key):
        w = [b'\x00\x00\x00\x00'] * (AesGlobals.NB * (AesGlobals.NR + 1))

        for i in range(AesGlobals.NK):
            w[i] = key[4 * i:4 * (i + 1)]

        for i in range(AesGlobals.NK, AesGlobals.NB * (AesGlobals.NR + 1)):
            temp = w[i - 1]
            if i % AesGlobals.NK == 0:
                temp = cls.__sub_word(cls.__rotate_word(temp))
                rcon = AesGlobals.RCON[i // AesGlobals.NK - 1].to_bytes(4, 'big')
                temp = cls.__xor_bytes(temp, rcon)
            w[i] = cls.__xor_bytes(temp, w[i - AesGlobals.NK])
        return w

    @classmethod
    def __xor_bytes(cls, a, b):
        return bytes(i ^ j for i, j in zip(a, b))

    @classmethod
    def __bytes2mat(cls, text):
        return [[text[row * AesGlobals.NB + col] for col in range(AesGlobals.NB)] for row in range(AesGlobals.NR_ROWS)]

    @classmethod
    def __mat2bytes(cls, mat):
        res = b''
        for row in range(AesGlobals.NR_ROWS):
            for col in range(AesGlobals.NB):
                res += bytes([mat[row][col]])
        return res

    @classmethod
    def __rotate_word(cls, word):
        return word[1:] + word[:1]

    @classmethod
    def __sub_word(cls, word):
        return bytes(AesGlobals.SBOX[b] for b in word)

    @classmethod
    def __sub_bytes(cls, state):
        for row in range(AesGlobals.NR_ROWS):
            for col in range(AesGlobals.NB):
                state[row][col] = AesGlobals.SBOX[state[row][col]]

    @classmethod
    def __shift_rows(cls, state):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]

    @classmethod
    def __inv_sub_bytes(cls, state):
        for row in range(AesGlobals.NR_ROWS):
            for col in range(AesGlobals.NB):
                state[row][col] = AesGlobals.INV_SBOX[state[row][col]]

    @classmethod
    def __inv_shift_rows(cls, state):
        state[1] = state[1][3:] + state[1][:3]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][1:] + state[3][:1]

    @classmethod
    def __inv_mix_columns(cls, state):
        for c in range(AesGlobals.NB):
            cls.__inv_mix_single_column([state[r][c] for r in range(AesGlobals.NR_ROWS)])

    @classmethod
    def __inv_mix_single_column(cls, s):
        s0, s1, s2, s3 = s[0], s[1], s[2], s[3]
        s[0] = cls.__gf_mult(0x0e, s0) ^ cls.__gf_mult(0x0b, s1) ^ cls.__gf_mult(0x0d, s2) ^ cls.__gf_mult(0x09, s3)
        s[1] = cls.__gf_mult(0x09, s0) ^ cls.__gf_mult(0x0e, s1) ^ cls.__gf_mult(0x0b, s2) ^ cls.__gf_mult(0x0d, s3)
        s[2] = cls.__gf_mult(0x0d, s0) ^ cls.__gf_mult(0x09, s1) ^ cls.__gf_mult(0x0e, s2) ^ cls.__gf_mult(0x0b, s3)
        s[3] = cls.__gf_mult(0x0b, s0) ^ cls.__gf_mult(0x0d, s1) ^ cls.__gf_mult(0x09, s2) ^ cls.__gf_mult(0x0e, s3)

    @classmethod
    def __mix_columns(cls, state):
        for c in range(AesGlobals.NB):
            cls.__mix_single_column([state[r][c] for r in range(AesGlobals.NR_ROWS)])

    @classmethod
    def __mix_single_column(cls, s):
        s0, s1, s2, s3 = s[0], s[1], s[2], s[3]
        s[0] = cls.__gf_mult(0x02, s0) ^ cls.__gf_mult(0x03, s1) ^ s2 ^ s3
        s[1] = s0 ^ cls.__gf_mult(0x02, s1) ^ cls.__gf_mult(0x03, s2) ^ s3
        s[2] = s0 ^ s1 ^ cls.__gf_mult(0x02, s2) ^ cls.__gf_mult(0x03, s3)
        s[3] = cls.__gf_mult(0x03, s0) ^ s1 ^ s2 ^ cls.__gf_mult(0x02, s3)

    @classmethod
    def __gf_mult(cls, a, b):
        product = 0
        for i in range(8):
            if (b & 1) == 1:
                product ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set == 0x80:
                a ^= 0x1B
            b >>= 1
        return product

    @classmethod
    def __add_round_key(cls, state, round_key):
        for row in range(AesGlobals.NR_ROWS):
            for col in range(AesGlobals.NB):
                state[row][col] ^= round_key[row][col]

    @classmethod
    def __check_block_size(cls, key):
        if len(key) != AesGlobals.BLOCK_SIZE:
            raise ValueError("Error: Key length must be 16 bytes (128 bits).")


def main():
    key = b"Sixteen byte key"
    plaintext = b"This is some longer text that needs AES encryption with padding. This string is big. Some text, random text, urban, kreml, zxc, brazil"
    ciphertext = AES.aes_encrypt(plaintext, key)
    print("Ciphertext:", ciphertext.hex() if ciphertext else "Encryption failed")
    decrypted_text = AES.aes_decrypt(ciphertext, key)
    print("Decrypted text:", decrypted_text)
    print("SUCCESS!!" if decrypted_text == plaintext else "FAILURE((")


# Run Tests
if __name__ == "__main__":
    main()
