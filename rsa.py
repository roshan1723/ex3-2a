from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os

# ======== support functions for part b and d ========
def find_decrypt_key(message, dir="key_pairs/"):
    # iterate through all the keys in the directory
    for file in os.listdir(dir):
        # TODO: what type of key should we filter out?
        #we should filter out the public keys,
        #because we need the private one to decrypt
        if not file.endswith("_priv.pem"): 
            continue # skip to the next file
        elif decrypt_message(message, dir + file, "temp.txt"): # if the decryption is successful
            os.remove("temp.txt") # remove the temporary file
            return dir + file # return the private key file name

def find_sign_key(message, signature, dir="key_pairs/"):
    # [IMPLEMENT THIS FUNCTION TO RETURN THE PATH TOWARDS THE PUBLIC KEY]
    # TODO
    for file in os.listdir(dir):
        if not file.endswith("_pub.pem"):
            continue
        elif verify_message(message, signature, dir + file):
            return dir + file

# ======== main functions ========
# Generate a public/private key pair using 2048 bits key length
def generate_keys(public_fname="public.pem", private_fname="private.pem"):
    # generate the key pair
    key = RSA.generate(2048)

    # ======= public key =======
    # TODO: extract the public key

    # TODO: save the public key in a file called public.pem
    with open(public_fname, 'wb') as public_file:
        public_file.write(key.publickey().exportKey())

    # ======= private key =======
    # TODO: extract the private key

    # TODO: save the private key in a file called private.pem
    with open(private_fname, 'wb') as private_file:
        private_file.write(key.exportKey())

# Encrypt a message using a public key
def encrypt_message(message, pub_key_path, out_fname="encrypted.txt"):
    # TODO: open the file to write the encrypted message
    with open(pub_key_path, 'rb') as public_file:
        public_key = RSA.import_key(public_file.read())

    # TODO: encrypt the message with the public RSA key using PKCS1_OAEP
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message)

    # TODO: write the encrypted message to the file

    # TODO: close the file
    
    with open(out_fname, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_message)
    # pass # remove this line when you implement the function

# Decrypt a message using a private key
def decrypt_message(message, priv_key_path, out_fname="decrypted.txt"):
    # TODO: open the file to write the decrypted message
    with open(priv_key_path, 'rb') as private_file:
        private_key = RSA.import_key(private_file.read())
    # decrypt the message with the private RSA key using PKCS1_OAEP
    # and return True if the decryption is successful
    try:
        # TODO: import private key and generate cipher using PKCS1_OAEP
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher.decrypt(message)
        # TODO: write the decrypted message to the file
        
        # TODO: close the file
        with open(out_fname, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_message)
        # return True if decryption is successful
        print("The private key is valid.")
        return True
    
    except ValueError:
        # return False if decryption is unsuccessful
        print("The private key is invalid.")
        return False

# Sign a message using a private key
def sign_message(message, priv_key_path, out_fname="signed_msg.txt"):
    # TODO: open the file to write the signature

    # TODO: import private key
    with open(priv_key_path, 'rb') as private_file:
        private_key = RSA.import_key(private_file.read())
    # TODO: hash the message with SHA256
    hash_message = SHA256.new(message)
    # TODO: sign the message with the private RSA key using pkcs1_15
    signature = pkcs1_15.new(private_key).sign(hash_message)
    # TODO: write the signature to the file

    # TODO: close the file
    with open(out_fname, 'wb') as signature_file:
        signature_file.write(signature)

# Verify a message using a public key
def verify_message(message, signature, public_key_path):
    # TODO: import public key
    with open(public_key_path, 'rb') as public_file:
        public_key = RSA.import_key(public_file.read())

    # TODO: hash the message with SHA256
    hash_message = SHA256.new(message)

    # verify the signature with the public RSA key using pkcs1_15
    try:
        # TODO: verify the signature
        pkcs1_15.new(public_key).verify(hash_message, signature)

        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False


def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('a. Generate public and private keys')
    print('b. Find the right key and decrypt the message in sus.txt')
    print('c. Sign a message and verify it')
    print('d. Find Miss Reveille\'s key pair that she used to sign rev.txt')
    print('q. Quit')
    print('***********************************************\n')

if __name__ == "__main__":
    while True:
        print_menu()
        option = input('Choose a menu option: ')
        if option == "a":
            # part a.1: generate public and private keys
            # TODO
            generate_keys()

            # part a.2: ask a message to be encrypted and encrypt it
            message = input("Enter a message to be encrypted: ")
            message = message.encode()
            public_key_path = "public.pem"
            # TODO: call the encrypt_message function
            encrypt_message(message, public_key_path)

            # part a.3: decrypt that exact message and output it to a file 
            #           called decrypted.txt
            private_key_path = "private.pem"
            encrypted_message = open("encrypted.txt", "rb").read()
            # TODO: call the decrypt_message function
            decrypt_message(encrypted_message, private_key_path)
            
        elif option == "b":
            # part b: decrypt the message given in sus.txt using one of the keys in key_pairs
            #         and output the decrypted message to a file called sus_decrypted.txt
            #         HINT: use the find_decrypt_key function to your advantage
            message = open("sus.txt", "rb").read()
            # TODO
            decrypt_key_path = find_decrypt_key(message) #error handling?
            # print(decrypt_key)
            decrypt_message(message, decrypt_key_path, "sus_decrypted.txt")
            
        elif option == "c":
            # part c.1: sign a message using the private key from part a.1
            #           and export the signature to a file called signed_msg.txt
            message = input("Enter a message to be signed: ")
            message = message.encode()
            private_key_path = "private.pem"
            # TODO: call the sign_message function
            sign_message(message, private_key_path)

            # part c.2: verify the signature of the message using 
            #           the public key from part a.1 
            public_key_path = "public.pem"
            signature = open("signed_msg.txt", "rb").read()
            # TODO: call the verify_message function
            is_valid = verify_message(message, signature, public_key_path)

        elif option == "d":
            # part d: identify the real Reveille's signature
            #         by verifying the signature of the message in 
            #         sus_decrypted.txt
            #         HINT:
            #         - think about how to find the correct key IRL (trial and error)
            #         - you are more than welcome to write a helper function to find the key
            #           and if you do, you can write find_sign_key() function
            #         - whatever method you use, as long as we select this option and get the
            #           correct key, you will get full credit
            message = open("sus_decrypted.txt", "rb").read()
            signature = open("rev.txt", "rb").read()
            # TODO
            valid_key = find_sign_key(message, signature)
            if valid_key:
                print(f"The valid key is: {valid_key}")
            else:
                print("No valid key found.")
            
        elif option == "q":
            break
