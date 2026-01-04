#!/usr/bin/env python3
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_private_key(priv_key_file):
    # Doc private key tu file PEM
    try:
        with open(priv_key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,  # khong co password
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        print(f"Loi doc private key: {e}", file=sys.stderr)
        sys.exit(1)


def decrypt_file(private_key, cipher_file, plain_file):
    # Giai ma ciphertext bang RSA private key
    try:
        # Doc ciphertext
        with open(cipher_file, 'rb') as f:
            ciphertext = f.read()
        
        # Lay key size
        key_size = private_key.key_size
        # Block size = key size
        block_size = key_size // 8
        
        # Check ciphertext size
        if len(ciphertext) % block_size != 0:
            print(f"Warning: Ciphertext size ({len(ciphertext)} bytes) khong chia het cho block size ({block_size} bytes)", file=sys.stderr)
        
        # Chia ciphertext thanh cac block
        num_blocks = len(ciphertext) // block_size
        plaintext_blocks = []
        
        for i in range(num_blocks):
            block = ciphertext[i * block_size:(i + 1) * block_size]
            
            # Decrypt block voi PKCS#1 v1.5 (giong OpenSSL)
            try:
                plain_block = private_key.decrypt(
                    block,
                    padding.PKCS1v15()
                )
                plaintext_blocks.append(plain_block)
            except Exception as e:
                print(f"Loi decrypt block {i + 1}: {e}", file=sys.stderr)
                sys.exit(1)
        
        # Ghi plaintext ra file
        with open(plain_file, 'wb') as f:
            for block in plaintext_blocks:
                f.write(block)
        
        print(f"Decrypt OK!")
        print(f"Ciphertext: {len(ciphertext)} bytes")
        print(f"Plaintext: {sum(len(b) for b in plaintext_blocks)} bytes")
        print(f"Blocks: {len(plaintext_blocks)}")
        
    except Exception as e:
        print(f"Loi decrypt: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) != 4:
        print("Usage: python rsa_decrypt.py <priv.pem> <cipher> <plain>", file=sys.stderr)
        print("  priv.pem: RSA private key file", file=sys.stderr)
        print("  cipher:   Ciphertext file", file=sys.stderr)
        print("  plain:    Output plaintext file", file=sys.stderr)
        sys.exit(1)
    
    priv_key_file = sys.argv[1]
    cipher_file = sys.argv[2]
    plain_file = sys.argv[3]
    
    # Load private key
    print(f"Loading private key tu {priv_key_file}...")
    private_key = load_private_key(priv_key_file)
    
    print(f"Key size: {private_key.key_size} bits")
    
    # Decrypt
    print(f"Decrypting {cipher_file}...")
    decrypt_file(private_key, cipher_file, plain_file)
    
    print(f"Plaintext saved: {plain_file}")


if __name__ == "__main__":
    main()
