import hashlib
import sys
import secrets
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


# The car verifies that the public key of the trinket
# is contained in the key store located in the physical memory of the car
def validate(public_key):
    return True

# The car generate unique challenge for trinket
def generate_challenge():
    return secrets.token_hex(nbytes=64)

# The trinket generate hash from the command and challenge
def generate_hash(command, challenge):
    return SHA256.new((command+challenge).encode())

# The trinket sign hash
def sign(hash,private_key):
    signature = pkcs1_15.new(private_key).sign(hash)
    return signature




if __name__ == '__main__':

    # only on trinket side
    private_key = RSA.generate(1024)
    # public visibility
    public_key = private_key.publickey()

    # trinket side
    hand_shake = {'msg': 'hello', 'public_key':  ''}
    print("#1 Handshake: trinket->car send data: {}".format(hand_shake))
    print(public_key.export_key().decode())

    # car side
    print("#2 Checking key: car searches for the same key in the storage")
    if validate(public_key):
        print("Successful: key is found")
    else:
        sys.exit()

    challenge = generate_challenge()
    print("#3 Challenge: car->trinket send data: {}".format(challenge))

    # trinket side
    command = "open"
    hash = generate_hash(command,challenge)
    print("#4 Trinket calculate hash using command and challenge: {}".format({'hash':hash.hexdigest()}))
    response = {"command":command,"signature":sign(hash,private_key).hex()}
    print("#5 Response (command + signed hash): trinket->car send data: {}".format(response))

    # car side
    hash = generate_hash(response['command'],challenge)
    print("#6 Car checking signature using public key")
    try:
        pkcs1_15.new(public_key).verify(hash, bytes.fromhex(response["signature"]))
        print("#7 The signature is correct: execute command: {}".format(command))
    except (ValueError, TypeError):
        print("The signature is not valid.")












