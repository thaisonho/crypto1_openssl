#!/usr/bin/env python3
"""
Chương trình mã hóa RSA
Sử dụng khóa công khai để mã hóa bản rõ thành bản mã
Tương thích với OpenSSL
"""

import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_public_key(pub_key_file):
    """
    Đọc khóa công khai từ file PEM
    
    Args:
        pub_key_file: Đường dẫn đến file chứa khóa công khai
        
    Returns:
        Đối tượng RSAPublicKey
    """
    try:
        with open(pub_key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        print(f"Lỗi khi đọc khóa công khai: {e}", file=sys.stderr)
        sys.exit(1)


def encrypt_file(public_key, plain_file, cipher_file):
    """
    Mã hóa file bản rõ sử dụng khóa công khai RSA
    
    Args:
        public_key: Đối tượng RSAPublicKey
        plain_file: Đường dẫn đến file bản rõ
        cipher_file: Đường dẫn đến file bản mã đầu ra
    """
    try:
        # Đọc bản rõ
        with open(plain_file, 'rb') as f:
            plaintext = f.read()
        
        # Lấy kích thước khóa
        key_size = public_key.key_size
        # Kích thước khối tối đa với PKCS#1 v1.5 padding (11 bytes overhead)
        max_block_size = (key_size // 8) - 11
        
        # Chia bản rõ thành các khối nếu cần
        ciphertext_blocks = []
        
        for i in range(0, len(plaintext), max_block_size):
            block = plaintext[i:i + max_block_size]
            
            # Mã hóa khối sử dụng PKCS#1 v1.5 padding (tương thích với OpenSSL)
            cipher_block = public_key.encrypt(
                block,
                padding.PKCS1v15()
            )
            ciphertext_blocks.append(cipher_block)
        
        # Ghi bản mã
        with open(cipher_file, 'wb') as f:
            for block in ciphertext_blocks:
                f.write(block)
        
        print(f"Mã hóa thành công!")
        print(f"Bản rõ: {len(plaintext)} bytes")
        print(f"Bản mã: {sum(len(b) for b in ciphertext_blocks)} bytes")
        print(f"Số khối: {len(ciphertext_blocks)}")
        
    except Exception as e:
        print(f"Lỗi khi mã hóa: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """
    Hàm main của chương trình
    """
    if len(sys.argv) != 4:
        print("Sử dụng: python rsa_encrypt.py <pub.pem> <plain> <cipher>", file=sys.stderr)
        print("  pub.pem: File chứa khóa công khai RSA", file=sys.stderr)
        print("  plain:   File chứa bản rõ cần mã hóa", file=sys.stderr)
        print("  cipher:  File chứa bản mã đầu ra", file=sys.stderr)
        sys.exit(1)
    
    pub_key_file = sys.argv[1]
    plain_file = sys.argv[2]
    cipher_file = sys.argv[3]
    
    # Đọc khóa công khai
    print(f"Đang đọc khóa công khai từ {pub_key_file}...")
    public_key = load_public_key(pub_key_file)
    
    print(f"Kích thước khóa: {public_key.key_size} bits")
    
    # Mã hóa
    print(f"Đang mã hóa {plain_file}...")
    encrypt_file(public_key, plain_file, cipher_file)
    
    print(f"Bản mã được lưu tại: {cipher_file}")


if __name__ == "__main__":
    main()
