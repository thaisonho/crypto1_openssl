#!/usr/bin/env python3
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_public_key(pub_key_file):
    # Doc public key tu file PEM
    try:
        with open(pub_key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        print(f"Loi doc public key: {e}", file=sys.stderr)
        sys.exit(1)


def encrypt_file(public_key, plain_file, cipher_file):
    # Ma hoa file plaintext bang RSA public key
    try:
        # Doc plaintext
        with open(plain_file, 'rb') as f:
            plaintext = f.read()
        
        # Lay key size
        key_size = public_key.key_size
        # Block size toi da voi PKCS#1 v1.5 (tru 11 bytes padding)
        max_block_size = (key_size // 8) - 11
        
        # Chia plaintext thanh cac block
        ciphertext_blocks = []
        
        for i in range(0, len(plaintext), max_block_size):
            block = plaintext[i:i + max_block_size]
            
            # Encrypt block voi PKCS#1 v1.5 (giong OpenSSL)
            cipher_block = public_key.encrypt(
                block,
                padding.PKCS1v15()
            )
            ciphertext_blocks.append(cipher_block)
        
        # Ghi ciphertext ra file
        with open(cipher_file, 'wb') as f:
            for block in ciphertext_blocks:
                f.write(block)
        
        print(f"Encrypt OK!")
        print(f"Plaintext: {len(plaintext)} bytes")
        print(f"Ciphertext: {sum(len(b) for b in ciphertext_blocks)} bytes")
        print(f"Blocks: {len(ciphertext_blocks)}")
        
    except Exception as e:
        print(f"Loi encrypt: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) != 4:
        print("Usage: python rsa_encrypt.py <pub.pem> <plain> <cipher>", file=sys.stderr)
        print("  pub.pem: RSA public key file", file=sys.stderr)
        print("  plain:   Plaintext file", file=sys.stderr)
        print("  cipher:  Output ciphertext file", file=sys.stderr)
        sys.exit(1)
    
    pub_key_file = sys.argv[1]
    plain_file = sys.argv[2]
    cipher_file = sys.argv[3]
    
    # Load public key
    print(f"Loading public key tu {pub_key_file}...")
    public_key = load_public_key(pub_key_file)
    
    print(f"Key size: {public_key.key_size} bits")
    
    # Encrypt
    print(f"Encrypting {plain_file}...")
    encrypt_file(public_key, plain_file, cipher_file)
    
    print(f"Ciphertext saved: {cipher_file}")


if __name__ == "__main__":
    main()
