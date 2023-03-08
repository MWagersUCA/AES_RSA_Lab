import rsa

def generateKeys():
    (publicKey, privateKey) = rsa.newkeys(1024)
    with open('keys/publicKey.pem', 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))
    with open('keys/privateKey.pem', 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))

def loadKeys():
    with open('keys/publicKey.pem', 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    with open('keys/privateKey.pem', 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    return privateKey, publicKey

def encrypt(message, key):
    return rsa.encrypt(message.encode('utf-8'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('utf-8')
    except rsa.DecryptionError:
        return False
    
def sign(message, key):
    return rsa.sign(message.encode('utf-8'), key, 'SHA-1')

def verify(message, signature, key):
    try:
        return rsa.verify(message.encode('utf-8'), signature, key, 'SHA-1')
    except rsa.VerificationError:
        return False
    
generateKeys()
privateKey, publicKey = loadKeys()

message = input('Write your message here:')
ciphertext = encrypt(message, publicKey)

signature = sign(message, privateKey)

text = decrypt(ciphertext, privateKey)

print(f'Cipher text: {ciphertext}')
print(f'Signature: {signature}')

if text:
    print(f'Message text: {text}')
else:
    print(f'Unable to decrypt the message.')

if verify(text, signature, publicKey):
    print('Successfully verified signature')
else:
    print('The message signature could not be verified')
