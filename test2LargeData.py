import math
import random
import hashlib
import time
import base64
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


# AES encryption and decryption functions
def aes_encrypt(plaintext, key):
    # implementation of AES encryption
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return (ciphertext, cipher.nonce, tag)

def aes_decrypt(ciphertext, key):
    # implementation of AES decryption
    cipher = AES.new(key, AES.MODE_EAX, nonce=ciphertext[1])
    decryptedtext = cipher.decrypt_and_verify(ciphertext[0], ciphertext[2])
    return decryptedtext

def rsa_encrypt(plaintext, public_key):
    n, e = public_key
    plaintext = int.from_bytes(plaintext, byteorder='big')
    ciphertext = pow(plaintext, e, n)
    ciphertext_bytes = ciphertext.to_bytes((ciphertext.bit_length() + 7) // 8, byteorder='big')
    return base64.b64encode(ciphertext_bytes)

def rsa_decrypt(ciphertext, private_key):
    ciphertext = base64.b64decode(ciphertext)
    n, d = private_key
    ciphertext = int.from_bytes(ciphertext, byteorder='big')
    plaintext = pow(ciphertext, d, n)
    plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')
    return plaintext_bytes

# function to generate random plaintext
def generate_plaintext():
    # implementation to generate plaintext
    return bytearray(random.getrandbits(8) for _ in range(16))

# function to generate AES key
def generate_aes_key(key_size):
    key = bytearray(key_size // 8)
    for i in range(key_size // 8):
        key[i] = random.randint(0, 255)
    return key

# function to generate RSA key pair
def generate_rsa_key_pair(key_size):
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537 # 2^16 + 1
    d = pow(e, -1, phi)
    return ((e, n), (d, n))

# function to generate prime number
def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p
        
# function to check if a number is prime
def is_prime(n, k=5):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    else:
        r, s = 0, n-1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randrange(2, n-1)
            x = pow(a, s, n)
            if x == 1 or x == n-1:
                continue
            for _ in range(r-1):
                x = pow(x, 2, n)
                if x == n-1:
                    break
            else:
                return False
        return True
        

# function to perform pattern analysis
def pattern_analysis():
    # implementation of pattern analysis
    # Generate 20 pairs of 512-bit plaintexts that differ by only 1-bit
    plaintext_pairs = []
    for i in range(20):
        plain1 = bytearray(random.getrandbits(8) for _ in range(64))
        plain2 = plain1.copy()
        bit_to_flip = random.randint(0, 511)
        byte_index = bit_to_flip // 8
        bit_index = bit_to_flip % 8
        plain2[byte_index] ^= 1 << bit_index
        plaintext_pairs.append((plain1, plain2))

    # Calculate the average bit differences in the ciphertext for each pair for AES
    aes_differences = []
    for plain1, plain2 in plaintext_pairs:
        key = bytearray(random.getrandbits(8) for _ in range(16))
        cipher = AES.new(bytes(key), AES.MODE_ECB)
        cipher1 = cipher.encrypt(bytes(plain1))
        cipher2 = cipher.encrypt(bytes(plain2))
        difference = sum(bin(x ^ y).count('1') for x, y in zip(cipher1, cipher2))
        aes_differences.append(difference / 512)

    # Calculate the average bit differences in the ciphertext for each pair for RSA
    rsa_differences = []
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    for plain1, plain2 in plaintext_pairs:
        cipher1 = PKCS1_OAEP.new(public_key).encrypt(bytes(plain1))
        cipher2 = PKCS1_OAEP.new(public_key).encrypt(bytes(plain2))
        difference = sum(bin(x ^ y).count('1') for x, y in zip(cipher1, cipher2))
        rsa_differences.append(difference / 512)

    # Return the results
    return aes_differences, rsa_differences

def test_aes(key_size, data_size):
    # generate random plaintext of given size
    plaintext = bytearray(random.getrandbits(8) for _ in range(data_size))

    # generate AES key
    key = generate_aes_key(key_size)

    # measure encryption time
    start_time = time.time()
    ciphertext, nonce, tag = aes_encrypt(plaintext, key)
    encryption_time = time.time() - start_time

    # measure decryption time
    start_time = time.time()
    decryptedtext = aes_decrypt((ciphertext, nonce, tag), key)
    decryption_time = time.time() - start_time

    # check if encryption and decryption are correct
    assert decryptedtext == plaintext, "AES decryption failed"

    return encryption_time, decryption_time

def test_rsa():
    key = RSA.generate(2048)

    cipher = PKCS1_OAEP.new(key)
    decrypt_cipher = PKCS1_OAEP.new(key)

    data = os.urandom(1024 * 1024 * 10)  # 10 MB of random data

    # Encrypt data in chunks
    start_time = time.monotonic()
    chunk_size = 1024  # 1 KB
    encrypted_data = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_data += encrypted_chunk
    encryption_time = time.monotonic() - start_time

    # Decrypt data in chunks
    start_time = time.monotonic()
    decrypted_data = bytearray()
    for i in range(0, len(encrypted_data), chunk_size + 128):  # 128 is the overhead for PKCS1_OAEP
        chunk = encrypted_data[i:i+chunk_size+128]
        decrypted_chunk = decrypt_cipher.decrypt(chunk)
        decrypted_data += decrypted_chunk
    decryption_time = time.monotonic() - start_time

    print(f"Encryption time: {encryption_time:.2f}s")
    print(f"Decryption time: {decryption_time:.2f}s")
    assert decrypted_data == data

# function to test AES and RSA execution times
def test_execution_times():
    # implementation of execution time testing
    # tabulate the average execution times for different key sizes
    print("AES key size\tAverage execution time")
    for key_size in [128, 192, 256]:
        avg_time = test_aes(key_size)
        print(f"{key_size}\t\t{avg_time:.6f}")

    print("\nRSA key size\tAverage execution time")
    for key_size in [1024, 2048, 4096]:
        avg_time = test_rsa(key_size)
        print(f"{key_size}\t\t{avg_time:.6f}")

# test AES and RSA processing times
key_sizes_aes = [128, 196, 256]
key_sizes_rsa = [1024, 2048, 4096]

for key_size in key_sizes_aes:
    key = generate_aes_key(key_size)
    plaintext = generate_plaintext()
    start_time = time.time()
    ciphertext = aes_encrypt(plaintext, key)
    end_time = time.time()
    print("AES encryption time for key size", key_size, "is", end_time - start_time, "seconds")
    start_time = time.time()
    decrypted_text = aes_decrypt(ciphertext, key)
    end_time = time.time()
    print("AES decryption time for key size", key_size, "is", end_time - start_time, "seconds")

for key_size in key_sizes_rsa:
    public_key, private_key = generate_rsa_key_pair(key_size)
    plaintext = generate_plaintext()
    start_time = time.time()
    ciphertext = rsa_encrypt(plaintext, public_key)
    end_time = time.time()
    print("RSA encryption time for key size", key_size, "is", end_time - start_time, "seconds")
    start_time = time.time()
    decrypted_text = rsa_decrypt(ciphertext, private_key)
    end_time = time.time()
    print("RSA decryption time for key size", key_size, "is", end_time - start_time, "seconds")

# perform pattern analysis
#print(pattern_analysis())
encryption_time, decryption_time = test_aes(256, 1024*1024*1024)
print(encryption_time, decryption_time)
# test AES and RSA execution times for different data inputs
#test_execution_times()


test_rsa()
