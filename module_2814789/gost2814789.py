import secrets

S_BOX = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 11, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
]

C1_const = '00000001000000010000000100000100'
C2_const = '00000001000000010000000100000001'


def text_to_unicode(text):  # формат 'U+0000'
    unicode_codes = [f"U+{ord(char):04X}" for char in text]
    return unicode_codes


def unicode_to_text(hex_array):
    text = ''
    for hex in hex_array:
        text += chr(int(f"0x{hex[2:]}", 16))
    return text


def unicode_to_bits(hex_array):
    bin_array = []
    for hex in hex_array:
        decimal_value = int(hex[2:], 16)
        binary_value = format(decimal_value, '016b')
        bin_array.append(binary_value)
    return bin_array


def bits_to_unicode(bits):  # bits - строка сообщения в двоичном формате
    hex_array = []
    bits_length = len(bits)
    hex_amount = bits_length // 16
    for i in range(hex_amount):
        hex = f"U+{int(bits[16 * i : 16 * i + 16], 2):04X}"
        hex_array.append(hex)
    return hex_array


def generate_sync_signal():
    sync_signal = bin(secrets.randbits(64))[2:]
    sync_signal = sync_signal.rjust(64, '0')
    return sync_signal


def key_generator():
    key = bin(secrets.randbits(256))[2:]
    key = key.rjust(256, '0')
    x0 = key[:32][::-1]
    x1 = key[32:64][::-1]
    x2 = key[64:96][::-1]
    x3 = key[96:128][::-1]
    x4 = key[128:160][::-1]
    x5 = key[160:192][::-1]
    x6 = key[192:224][::-1]
    x7 = key[224:256][::-1]
    keys = [x0, x1, x2, x3, x4, x5, x6, x7]
    return keys


#keys = key_generator()
#print(keys, 'Ключи из модуля', sep='\n\n\n\n')


def round_simp_repl(n1, n2, key, s_box):
    n1_old = n1  # n1 и n2 представлены в виде '101001010...'
    #  key представлен в виде '101010010...'
    n1 = bin((int(n1, 2) + int(key, 2)) % 2**32)[2:].rjust(32, '0')
    n1_slices = []
    k_slices = ''
    for i in range(0, len(n1), 4):  # преобразование данных на вход в блок подстановки К
        n1_slices.append(n1[i:i+4])
    # s_row это отдельный список из S_BOX
    for i in range(0, len(n1_slices)):  # блок подстановки К
        k_slices += bin(s_box[i][int(n1_slices[i], 2)])[2:].rjust(4, '0')
    k_slices_shifted = k_slices[11:] + k_slices[:11]  # первые 11 цифр в виде среза переносятся в конец
    n1, n2 = bin(int(k_slices_shifted, 2) ^ int(n2, 2))[2:].rjust(32, '0'), n1_old
    return n1, n2, n1_slices, k_slices, k_slices_shifted


def generate_gamma(n1, n2, message_length):
    steps_gamma = []
    gamma_array = []
    n3 = n1
    n4 = n2
    # Вычисляется количество гаммы, которую необходимо сгенерировать
    ammount_of_gamma = (message_length // 64 if message_length % 64 == 0 else message_length // 64 + 1) if (
            message_length > 64) else 1
    for i in range(1, ammount_of_gamma + 1):
        n4 = bin((int(n4, 2) + int(C1_const, 2)) % ((2 ** 32) - 1))[2:].rjust(32, '0')
        n3 = bin((int(n3, 2) + int(C2_const, 2)) % (2 ** 32))[2:].rjust(32, '0')
        n1 = n3
        n2 = n4
        for j in range(1, 25):
            step = dict()
            step['n1_old'] = n1
            step['n2_old'] = n2
            n1, n2, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[(j - 1) % 8], S_BOX)
            step['number'] = (j - 1) % 8
            step['n1_new'] = n1
            step['n2_new'] = n2
            step['n1_slices'] = n1_slices
            step['k_slices'] = k_slices
            step['k_slices_shifted'] = k_slices_shifted
            steps_gamma.append(step)

        for j in range(25, 32):
            step = dict()
            step['n1_old'] = n1
            step['n2_old'] = n2
            n1, n2, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[32 - j], S_BOX)
            step['number'] = 32 - j
            step['n1_new'] = n1
            step['n2_new'] = n2
            step['n1_slices'] = n1_slices
            step['k_slices'] = k_slices
            step['k_slices_shifted'] = k_slices_shifted
            steps_gamma.append(step)

        # 32 цикл
        step = dict()
        step['n1_old'] = n1
        step['n2_old'] = n2
        n2, n1, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[0], S_BOX)
        step['number'] = 32
        step['n1_new'] = n1
        step['n2_new'] = n2
        step['n1_slices'] = n1_slices
        step['k_slices'] = k_slices
        step['k_slices_shifted'] = k_slices_shifted
        steps_gamma.append(step)
        gamma_array.append(n1 + n2)
    return gamma_array, steps_gamma

def gost2814789_gamma(message):
    message = message
    message_bits = ''.join(unicode_to_bits(text_to_unicode(message)))
    message_length = len(message_bits)
    sync_signal = generate_sync_signal()
    global keys
    print(keys)
    n1_res, n2_res = 0, 0
    n1 = sync_signal[:32][::-1]
    n2 = sync_signal[32:64][::-1]
    n1_slices, k_slices, k_slices_shifted = 0, 0, 0
    n3, n4 = 0, 0
    steps = []
    steps_gamma = []
    gamma_array = []

    for j in range(1, 25):
        step = dict()
        step['n1_old'] = n1
        step['n2_old'] = n2
        n1, n2, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[(j - 1) % 8], S_BOX)
        step['number'] = (j - 1) % 8
        step['n1_new'] = n1
        step['n2_new'] = n2
        step['n1_slices'] = n1_slices
        step['k_slices'] = k_slices
        step['k_slices_shifted'] = k_slices_shifted
        steps.append(step)

    for j in range(25, 32):
        step = dict()
        step['n1_old'] = n1
        step['n2_old'] = n2
        n1, n2, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[32 - j], S_BOX)
        step['number'] = 32 - j
        step['n1_new'] = n1
        step['n2_new'] = n2
        step['n1_slices'] = n1_slices
        step['k_slices'] = k_slices
        step['k_slices_shifted'] = k_slices_shifted
        steps.append(step)

    # 32 цикл
    step = dict()
    step['n1_old'] = n1
    step['n2_old'] = n2
    n2, n1, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[0], S_BOX)
    step['number'] = 32
    step['n1_new'] = n1
    step['n2_new'] = n2
    step['n1_slices'] = n1_slices
    step['k_slices'] = k_slices
    step['k_slices_shifted'] = k_slices_shifted
    steps.append(step)

    gamma_array, steps_gamma = generate_gamma(n1, n2, message_length)
    encrypted_bits = ''

    ammount_of_gamma = (message_length // 64 if message_length % 64 == 0 else message_length // 64 + 1) if (
            message_length > 64) else 1
    for i in range(ammount_of_gamma):
        message_block = message_bits[64 * i : 64 * i + 64]
        m1 = message_block[:32]
        m2 = message_block[32:]
        N1 = gamma_array[i][:32][::-1][:len(m1)]
        N2 = gamma_array[i][32:64][::-1][:len(m2)]
        encrypted_bits += bin(int(m1, 2) ^ int(N1, 2))[2:].rjust(len(m1), '0') if m1 != "" else ""
        encrypted_bits += bin(int(m2, 2) ^ int(N2, 2))[2:].rjust(len(m2), '0') if m2 != "" else ""
    print("Зашифрованное сообщение:")
    print(encrypted_bits)
    print("Длина зашифрованного сообщения:")
    print(len(encrypted_bits))
    encrypted_unicode = bits_to_unicode(encrypted_bits)
    encrypted_text = unicode_to_text(encrypted_unicode)

    # Расшифрование
    n1 = sync_signal[:32][::-1]
    n2 = sync_signal[32:64][::-1]
    steps = []
    n1_slices = []
    k_slices = ''
    k_slices_shifted = ''

    for j in range(1, 25):
        step = dict()
        step['n1_old'] = n1
        step['n2_old'] = n2
        n1, n2, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[(j - 1) % 8], S_BOX)
        step['number'] = (j - 1) % 8
        step['n1_new'] = n1
        step['n2_new'] = n2
        step['n1_slices'] = n1_slices
        step['k_slices'] = k_slices
        step['k_slices_shifted'] = k_slices_shifted
        steps.append(step)

    for j in range(25, 32):
        step = dict()
        step['n1_old'] = n1
        step['n2_old'] = n2
        n1, n2, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[32 - j], S_BOX)
        step['number'] = 32 - j
        step['n1_new'] = n1
        step['n2_new'] = n2
        step['n1_slices'] = n1_slices
        step['k_slices'] = k_slices
        step['k_slices_shifted'] = k_slices_shifted
        steps.append(step)

    # 32 цикл
    step = dict()
    step['n1_old'] = n1
    step['n2_old'] = n2
    n2, n1, n1_slices, k_slices, k_slices_shifted = round_simp_repl(n1, n2, keys[0], S_BOX)
    step['number'] = 32
    step['n1_new'] = n1
    step['n2_new'] = n2
    step['n1_slices'] = n1_slices
    step['k_slices'] = k_slices
    step['k_slices_shifted'] = k_slices_shifted
    steps.append(step)
    gamma_array, steps_gamma = generate_gamma(n1, n2, message_length)
    decrypted_bits = ''
    ammount_of_gamma = (message_length // 64 if message_length % 64 == 0 else message_length // 64 + 1) if (
            message_length > 64) else 1
    for i in range(ammount_of_gamma):
        message_block = encrypted_bits[64 * i : 64 * i + 64]
        m1 = message_block[:32]
        m2 = message_block[32:]
        N1 = gamma_array[i][:32][::-1][:len(m1)]
        N2 = gamma_array[i][32:64][::-1][:len(m2)]
        decrypted_bits += bin(int(m1, 2) ^ int(N1, 2))[2:].rjust(len(m1), '0') if m1 != "" else ""
        decrypted_bits += bin(int(m2, 2) ^ int(N2, 2))[2:].rjust(len(m2), '0') if m2 != "" else ""

    decrypted_unicode = bits_to_unicode(decrypted_bits)
    decrypted_text = unicode_to_text(decrypted_unicode)
    return encrypted_text, decrypted_text