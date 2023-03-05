from Crypto.PublicKey import RSA

# Generate RSA key pairs of different sizes
key_1024 = RSA.generate(1024)
key_2048 = RSA.generate(2048)
key_4096 = RSA.generate(4096)

# Print the private and public keys
print("Private key (1024 bits):\n", key_1024.export_key())
print("Public key (1024 bits):\n", key_1024.publickey().export_key())
print("Private key (2048 bits):\n", key_2048.export_key())
print("Public key (2048 bits):\n", key_2048.publickey().export_key())
print("Private key (4096 bits):\n", key_4096.export_key())
print("Public key (4096 bits):\n", key_4096.publickey().export_key())
