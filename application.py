from flask import Flask, render_template, request, jsonify
from module_2814789 import *

app = Flask(__name__)


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


@app.route('/about-gost2814789')
def about_gost28147():
    return render_template('about-gost2814789.html')


@app.route('/gost2814789', methods=['GET', 'POST'])
def gost2814789():
    if request.method == 'POST':
        data = request.json
        text = data.get('text', '')
        print(text)
        decrypt = data.get('decrypt', False)
        encrypted_text, decrypted_text = gost2814789_gamma(text)
        print(encrypted_text)
        print(decrypted_text)
        return jsonify({'steps': encrypted_text})
    return render_template('gost2814789.html')


@app.route('/aes', methods=['GET', 'POST'])
def aes():
    # Логика обработки AES
    return render_template('aes.html')


@app.route('/rsa', methods=['GET', 'POST'])
def rsa():
    # Логика обработки RSA
    return render_template('rsa.html')


@app.route('/rsa_explanation', methods=['GET', 'POST'])
def rsa_explanation():
    # Объяснение работы RSA
    return render_template('rsa_explanation.html')


@app.route('/gost_34_10_2018', methods=['GET', 'POST'])
def gost_34_10_2018():
    return render_template('gost_34_10_2018.html')


@app.route('/gost_34_10_2018_explanation', methods=['GET', 'POST'])
def gost_34_10_2018_explanation():
    return render_template('gost_34_10_2018_explanation.html')


if __name__ == '__main__':
    app.run(debug=True)
