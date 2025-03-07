from flask import Flask, render_template, request, jsonify
from module_gost_34_10_2018 import gost_2018
from module_aes import aes as aes_module
from module_gost_28147_89 import gost as gost_28147

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True


# Логика шифра Цезаря с промежуточными результатами
def caesar_cipher_with_steps(text, shift):
    alphabet = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'
    steps = []
    result_text = ''
    for char in text:
        if char.upper() in alphabet:
            original_index = alphabet.index(char.upper())
            new_index = (original_index + shift) % len(alphabet)
            new_char = alphabet[new_index]
            steps.append({
                'char': char,
                'original_index': original_index,
                'new_index': new_index,
                'new_char': new_char
            })
            result_text += new_char if char.isupper() else new_char.lower()
        else:
            steps.append({'char': char, 'original_index': None, 'new_index': None, 'new_char': char})
            result_text += char

    return steps


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/caesar', methods=['GET', 'POST'])
def caesar():
    if request.method == 'POST':
        data = request.json
        text = data.get('text', '')
        shift = int(data.get('shift', 0))

        # Проверяем, нужно ли расшифрование
        decrypt = data.get('decrypt', False)
        if decrypt:
            shift = -shift  # Отрицательный сдвиг для расшифрования

        steps = caesar_cipher_with_steps(text, shift)
        return jsonify({'steps': steps})
    return render_template('caesar.html')


@app.route('/gost_28147_89_explanation')
def gost_28147_89_explanation():
    return render_template('gost_28147_89_explanation.html')


@app.route('/gost_28147_89')
def gost_28147_89():
    return render_template('gost_28147_89.html')


@app.route('/gost_28147_89_encrypt', methods=['GET', 'POST'])
def gost_28147_89_encrypt():
    import traceback
    data = request.json
    try:
        return jsonify(gost_28147.encrypt(data))
    except Exception as e:
        print(e)
        traceback.print_exc()
        return jsonify({'errors': [e.__str__()]})


@app.route('/gost_28147_89_decrypt', methods=['GET', 'POST'])
def gost_28147_89_decrypt():
    import traceback
    data = request.json
    try:
        return jsonify(gost_28147.decrypt(data))
    except Exception as e:
        print(e)
        traceback.print_exc()
        return jsonify({'errors': [e.__str__()]})


@app.route('/rsa', methods=['GET', 'POST'])
def rsa():
    return render_template('rsa.html')


@app.route('/rsa_explanation', methods=['GET', 'POST'])
def rsa_explanation():
    return render_template('rsa_explanation.html')


@app.route('/gost_34_10_2018', methods=['GET', 'POST'])
def gost_34_10_2018():
    return render_template('gost_34_10_2018.html')


@app.route('/gost_34_10_2018_explanation', methods=['GET', 'POST'])
def gost_34_10_2018_explanation():
    return render_template('gost_34_10_2018_explanation.html')


@app.route('/gost_params', methods=['GET', 'POST'])
def gost_params():
    params = [
        {'p': 4919, 'a': 622, 'b': 482, 'P': (4900, 80), 'm': 4900, 'q': 7},
        {'p': 1447, 'a': 666, 'b': 576, 'P': (24, 38), 'm': 1412, 'q': 353},
        {'p': 6899, 'a': 680, 'b': 945, 'P': (489, 123), 'm': 6924, 'q': 577},
        {'p': 2239, 'a': 518, 'b': 51, 'P': (99, 98), 'm': 2209, 'q': 47},
        {'p': 5417, 'a': 180, 'b': 893, 'P': (183, 174), 'm': 5344, 'q': 167},
        {'p': 8317, 'a': 594, 'b': 359, 'P': (460, 98), 'm': 8356, 'q': 2089},
        {'p': 4051, 'a': 295, 'b': 190, 'P': (2780, 39), 'm': 4122, 'q': 3},
        {'p': 6163, 'a': 675, 'b': 88, 'P': (5314, 251), 'm': 6320, 'q': 5},
        {'p': 2237, 'a': 659, 'b': 971, 'P': (2, 134), 'm': 2221, 'q': 2221},
        {'p': 1451, 'a': 754, 'b': 464, 'P': (35, 9), 'm': 1524, 'q': 127},
        {'p': 6163, 'a': 437, 'b': 619, 'P': (2649, 226), 'm': 6194, 'q': 19},
        {'p': 7489, 'a': 575, 'b': 247, 'P': (285, 287), 'm': 7645, 'q': 139},
        {'p': 2281, 'a': 1000, 'b': 685, 'P': (288, 118), 'm': 2369, 'q': 23},
        {'p': 6311, 'a': 947, 'b': 553, 'P': (6233, 213), 'm': 6159, 'q': 3},
        {'p': 2851, 'a': 29, 'b': 41, 'P': (119, 81), 'm': 2758, 'q': 197},
        {'p': 3833, 'a': 646, 'b': 848, 'P': (1169, 67), 'm': 3850, 'q': 11},
        {'p': 1307, 'a': 493, 'b': 38, 'P': (24, 86), 'm': 1283, 'q': 1283},
        {'p': 6343, 'a': 818, 'b': 37, 'P': (859, 38), 'm': 6360, 'q': 5},
        {'p': 5081, 'a': 536, 'b': 193, 'P': (4304, 228), 'm': 4958, 'q': 37},
        {'p': 9811, 'a': 464, 'b': 620, 'P': (556, 65), 'm': 9953, 'q': 269},
        {'p': 8123, 'a': 884, 'b': 946, 'P': (1472, 67), 'm': 8086, 'q': 13},
        {'p': 7417, 'a': 959, 'b': 934, 'P': (1764, 29), 'm': 7456, 'q': 233},
        {'p': 8887, 'a': 517, 'b': 370, 'P': (450, 266), 'm': 8927, 'q': 79},
        {'p': 9257, 'a': 825, 'b': 115, 'P': (52, 286), 'm': 9076, 'q': 2269},
        {'p': 3313, 'a': 911, 'b': 35, 'P': (11, 69), 'm': 3239, 'q': 79},
        {'p': 9907, 'a': 250, 'b': 716, 'P': (1865, 212), 'm': 9976, 'q': 29},
        {'p': 1583, 'a': 593, 'b': 339, 'P': (81, 72), 'm': 1538, 'q': 769},
        {'p': 2423, 'a': 360, 'b': 946, 'P': (958, 131), 'm': 2475, 'q': 11},
        {'p': 8681, 'a': 891, 'b': 640, 'P': (2733, 248), 'm': 8664, 'q': 19},
        {'p': 3779, 'a': 812, 'b': 217, 'P': (94, 13), 'm': 3702, 'q': 617},
        {'p': 3607, 'a': 219, 'b': 808, 'P': (48, 188), 'm': 3661, 'q': 523},
        {'p': 7703, 'a': 663, 'b': 30, 'P': (3893, 145), 'm': 7667, 'q': 17},
        {'p': 6997, 'a': 758, 'b': 475, 'P': (256, 272), 'm': 7123, 'q': 17},
        {'p': 4637, 'a': 386, 'b': 73, 'P': (169, 9), 'm': 4774, 'q': 31},
        {'p': 2633, 'a': 527, 'b': 67, 'P': (112, 52), 'm': 2714, 'q': 59},
        {'p': 7229, 'a': 915, 'b': 129, 'P': (73, 149), 'm': 7295, 'q': 1459},
        {'p': 2267, 'a': 598, 'b': 69, 'P': (16, 151), 'm': 2250, 'q': 3},
        {'p': 6427, 'a': 586, 'b': 247, 'P': (2810, 215), 'm': 6443, 'q': 379},
        {'p': 3041, 'a': 880, 'b': 226, 'P': (83, 19), 'm': 2972, 'q': 743},
        {'p': 8263, 'a': 848, 'b': 769, 'P': (356, 85), 'm': 8305, 'q': 11},
    ]

    def make_extended_params(raw_param):
        obj_param = gost_2018.Params.from_dict(raw_param)
        raw_param['private_key'] = obj_param.private_key
        raw_param['public_key'] = obj_param.public_key
        return raw_param

    return jsonify({'params': list(map(make_extended_params, params))})


@app.route('/gost_validate_params', methods=['GET', 'POST'])
def gost_validate_params():
    data = request.json
    params = data.get('params', '')
    try:
        errors = gost_2018.validate_params(params)
    except Exception as e:
        errors = [{'key': 'server_error', 'message': e.__str__()}]
    return jsonify({'errors': errors})


@app.route('/gost_make_signature', methods=['GET', 'POST'])
def gost_make_signature():
    data = request.json
    raw_params = data.get('params', '')

    errors = gost_2018.validate_params(raw_params)
    if len(errors):
        return jsonify({'errors': errors})

    params = gost_2018.Params.from_dict(raw_params)
    message = data.get('message', None)
    if message is None:
        return jsonify({'errors': ['message is empty']})

    hasher = gost_2018.GostHasher(params)
    return jsonify({'signature': hasher.sign_message(message)})


@app.route('/gost_verify_signature', methods=['GET', 'POST'])
def gost_verify_signature():
    data = request.json
    raw_params = data.get('params', '')

    errors = gost_2018.validate_params(raw_params)
    if len(errors):
        return jsonify({'errors': errors})

    params = gost_2018.Params.from_dict(raw_params)
    message = data.get('message', None)
    signature = data.get('signature', None)
    if message is None or signature is None:
        return jsonify({'errors': ['message or signature is empty']})

    signature = tuple(map(int, signature.split(',')))
    hasher = gost_2018.GostHasher(params)
    return jsonify({'is_valid': hasher.verify_signature(message, signature)})


@app.route('/aes', methods=['GET', 'POST'])
def aes():
    # Логика обработки AES
    return render_template('aes.html')


@app.route('/aes_explanation', methods=['GET', 'POST'])
def aes_explanation():
    return render_template('aes_explanation.html')


@app.route('/aes_encrypt', methods=['GET', 'POST'])
def aes_encrypt():
    data = request.json
    message = data.get('message')
    key = data.get('key')
    try:
        errors = __validate_aes_params(message, key)
        if len(errors):
            return jsonify({'errors': errors})
        return jsonify(aes_module.encrypt(__to_bytes(message), __to_bytes(key)))
    except Exception as e:
        return jsonify({'errors': [e.__str__()]})


@app.route('/aes_decrypt', methods=['GET', 'POST'])
def aes_decrypt():
    data = request.json
    message = data.get('message')
    key = data.get('key')
    try:
        errors = __validate_aes_params(message, key)
        if len(errors):
            return jsonify({'errors': errors})
        __check_hex_correctance(message)
        return jsonify(aes_module.decrypt(bytes.fromhex(message), __to_bytes(key)))
    except Exception as e:
        return jsonify({'errors': [e.__str__()]})


def __check_hex_correctance(text):
    try:
        int(text, 16)
    except Exception as e:
        raise Exception('encoded message must be correct hex')


@app.route('/aes_params', methods=['GET', 'POST'])
def aes_params():
    return jsonify({'params': aes_module.AesGlobals.get_params()})


def __to_bytes(txt):
    return bytes(txt, 'utf-8')


def __validate_aes_params(message, key):
    errors = []
    if message is None:
        errors.append('Message not set')
    elif len(message) == 0:
        errors.append('Message must not be empty')
    if key is None:
        errors.append('Key not set')
    elif len(key) != aes_module.AesGlobals.BLOCK_SIZE:
        errors.append(f"Key size must be {aes_module.AesGlobals.BLOCK_SIZE}")
    return errors


if __name__ == '__main__':
    app.run(debug=True)
