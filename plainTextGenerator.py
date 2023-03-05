import random

# Generate a random 512-bit plaintext
plaintext = bin(random.getrandbits(512))[2:].zfill(512)

# Flip one bit of the plaintext to create the second plaintext
bit_to_flip = random.randint(0, 511)
plaintext1 = plaintext[:bit_to_flip] + str(1 - int(plaintext[bit_to_flip])) + plaintext[bit_to_flip+1:]
plaintext2 = plaintext
if plaintext1 != plaintext:
    plaintext2 = plaintext1
    plaintext1 = plaintext

# Print the plaintexts
print("Plaintext 1:", plaintext1)
print("Plaintext 2:", plaintext2)
