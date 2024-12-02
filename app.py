from flask import Flask, render_template, request, send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64
import math

app = Flask(__name__)

# Generate RSA Key Pair
def generate_key_pair():
    if not os.path.exists('keys'):
        os.makedirs('keys')

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open('keys/private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_key)
    
    with open('keys/public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_key)

# Atbash cipher function
def atbash_cipher(text):
    transformed = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            transformed += chr(base + (25 - (ord(char) - base)))
        else:
            transformed += char
    return transformed

# Vernam (OTP) cipher functions
def generate_otp(length):
    return os.urandom(length)

def vernam_encrypt(plaintext, otp):
    ciphertext = bytes([p ^ k for p, k in zip(plaintext.encode('utf-8'), otp)])
    return base64.b64encode(ciphertext).decode('utf-8')

def vernam_decrypt(ciphertext, otp):
    decoded = base64.b64decode(ciphertext)
    plaintext = ''.join(chr(c ^ k) for c, k in zip(decoded, otp))
    return plaintext

# Caesar cipher functions
def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Vigenère cipher functions
def vigenere_encrypt(plaintext, keyword):
    ciphertext = ""
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]
    for p, k in zip(plaintext, keyword_repeated):
        if p.isalpha():
            base = ord('A') if p.isupper() else ord('a')
            encrypted_char = chr((ord(p) - base + ord(k) - ord('A')) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += p
    return ciphertext

def vigenere_decrypt(ciphertext, keyword):
    return vigenere_encrypt(ciphertext, ''.join([chr((26 - (ord(k) - ord('A'))) % 26 + ord('A')) for k in keyword]))

# Transposition Columnar Cipher functions
def transposition_encrypt(text, key):
    key_length = len(key)
    grid = [''] * key_length
    for index, char in enumerate(text):
        grid[index % key_length] += char
    return ''.join(grid)

def transposition_decrypt(text, key):
    key_length = len(key)
    num_rows = math.ceil(len(text) / key_length)
    grid = [''] * num_rows
    column_height = len(text) // key_length
    extra_chars = len(text) % key_length

    index = 0
    for column in range(key_length):
        height = column_height + (1 if column < extra_chars else 0)
        grid[column] = text[index:index + height]
        index += height

    return ''.join([grid[col][row] for row in range(num_rows) for col in range(key_length) if row < len(grid[col])])


# File encryption
def encrypt_file(file_path, key_path, output_file_path, vigenere_key, caesar_shift, columnar_key):
    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())

    symmetric_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_symmetric_key = cipher_rsa.encrypt(symmetric_key)

    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    with open(file_path, 'rb') as file:
        plaintext = file.read()
        ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))

    # Apply Caesar cipher
    base64_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    caesar_ciphertext = caesar_encrypt(base64_ciphertext, caesar_shift)

    # Apply Vigenère cipher
    vigenere_ciphertext = vigenere_encrypt(caesar_ciphertext, vigenere_key)

    # Apply Transposition cipher
    transposition_ciphertext = transposition_encrypt(vigenere_ciphertext, columnar_key)

    # Apply Atbash cipher
    atbash_ciphertext = atbash_cipher(transposition_ciphertext)

    # Apply Vernam cipher
    otp = generate_otp(len(atbash_ciphertext))
    vernam_ciphertext = vernam_encrypt(atbash_ciphertext, otp)

    otp_str = base64.b64encode(otp).decode('utf-8')

    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(enc_symmetric_key)
        encrypted_file.write(cipher_aes.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(vernam_ciphertext.encode('utf-8'))

    return otp_str


def decrypt_file(file_path, key_path, output_file_path, vigenere_key, caesar_shift, otp, columnar_key):
    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())

    with open(file_path, 'rb') as encrypted_file:
        enc_symmetric_key = encrypted_file.read(256)
        nonce = encrypted_file.read(16)
        tag = encrypted_file.read(16)
        vernam_ciphertext = encrypted_file.read().decode('utf-8')

    cipher_rsa = PKCS1_OAEP.new(key)
    symmetric_key = cipher_rsa.decrypt(enc_symmetric_key)

    # Reverse Vernam cipher
    otp_bytes = base64.b64decode(otp)
    atbash_ciphertext = vernam_decrypt(vernam_ciphertext, otp_bytes)

    # Reverse Atbash cipher
    transposition_ciphertext = atbash_cipher(atbash_ciphertext)

    # Reverse Transposition cipher
    vigenere_ciphertext = transposition_decrypt(transposition_ciphertext, columnar_key)

    # Reverse Vigenère cipher
    caesar_ciphertext = vigenere_decrypt(vigenere_ciphertext, vigenere_key)

    # Reverse Caesar cipher
    base64_ciphertext = caesar_decrypt(caesar_ciphertext, caesar_shift)

    # Decode Base64 and decrypt with AES
    decoded_ciphertext = base64.b64decode(base64_ciphertext)
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    decrypted_bytes = unpad(cipher_aes.decrypt_and_verify(decoded_ciphertext, tag), AES.block_size)

    with open(output_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_bytes)


# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    operation = request.form['action']
    file = request.files['file']
    filename = 'uploaded_file' + os.path.splitext(file.filename)[-1]
    file_path = os.path.join('uploads', filename)
    file.save(file_path)

    vigenere_key = request.form['vigenere_key']
    caesar_shift = int(request.form['caesar_shift'])
    columnar_key = request.form['columnar_key']

    if operation == 'encrypt':
        output_filename = 'encrypted_file' + os.path.splitext(file.filename)[-1]
        output_file_path = os.path.join('uploads', output_filename)
        otp = encrypt_file(file_path, 'keys/public_key.pem', output_file_path, vigenere_key, caesar_shift, columnar_key)
        return render_template('download.html', operation=operation, filename=output_filename, file_type='encrypted', otp=otp)
    elif operation == 'decrypt':
        otp = request.form.get('vernam_key')  # Get the OTP from the form
        output_filename = 'decrypted_file' + os.path.splitext(file.filename)[-1]
        output_file_path = os.path.join('uploads', output_filename)
        decrypt_file(file_path, 'keys/private_key.pem', output_file_path, vigenere_key, caesar_shift, otp, columnar_key)
        return render_template('download.html', operation=operation, filename=output_filename, file_type='decrypted')


@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join('uploads', filename), as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    generate_key_pair()
    app.run(debug=True)
