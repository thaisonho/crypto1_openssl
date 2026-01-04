#!/usr/bin/env python3
"""
Chương trình giải mã RSA
Sử dụng khóa bí mật để giải mã bản mã thành bản rõ
Tương thích với OpenSSL
"""

import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_private_key(priv_key_file):
    """
    Đọc khóa bí mật từ file PEM
    
    Args:
        priv_key_file: Đường dẫn đến file chứa khóa bí mật
        
    Returns:
        Đối tượng RSAPrivateKey
    """
    try:
        with open(priv_key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,  # Không có mật khẩu
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        print(f"Lỗi khi đọc khóa bí mật: {e}", file=sys.stderr)
        sys.exit(1)


def decrypt_file(private_key, cipher_file, plain_file):
    """
    Giải mã file bản mã sử dụng khóa bí mật RSA
    
    Args:
        private_key: Đối tượng RSAPrivateKey
        cipher_file: Đường dẫn đến file bản mã
        plain_file: Đường dẫn đến file bản rõ đầu ra
    """
    try:
        # Đọc bản mã
        with open(cipher_file, 'rb') as f:
            ciphertext = f.read()
        
        # Lấy kích thước khóa
        key_size = private_key.key_size
        # Kích thước mỗi khối bản mã (bằng kích thước khóa)
        block_size = key_size // 8
        
        # Kiểm tra kích thước bản mã
        if len(ciphertext) % block_size != 0:
            print(f"Cảnh báo: Kích thước bản mã ({len(ciphertext)} bytes) không chia hết cho kích thước khối ({block_size} bytes)", file=sys.stderr)
        
        # Chia bản mã thành các khối
        num_blocks = len(ciphertext) // block_size
        plaintext_blocks = []
        
        for i in range(num_blocks):
            block = ciphertext[i * block_size:(i + 1) * block_size]
            
            # Giải mã khối sử dụng PKCS#1 v1.5 padding (tương thích với OpenSSL)
            try:
                plain_block = private_key.decrypt(
                    block,
                    padding.PKCS1v15()
                )
                plaintext_blocks.append(plain_block)
            except Exception as e:
                print(f"Lỗi khi giải mã khối {i + 1}: {e}", file=sys.stderr)
                sys.exit(1)
        
        # Ghi bản rõ
        with open(plain_file, 'wb') as f:
            for block in plaintext_blocks:
                f.write(block)
        
        print(f"Giải mã thành công!")
        print(f"Bản mã: {len(ciphertext)} bytes")
        print(f"Bản rõ: {sum(len(b) for b in plaintext_blocks)} bytes")
        print(f"Số khối: {len(plaintext_blocks)}")
        
    except Exception as e:
        print(f"Lỗi khi giải mã: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """
    Hàm main của chương trình
    """
    if len(sys.argv) != 4:
        print("Sử dụng: python rsa_decrypt.py <priv.pem> <cipher> <plain>", file=sys.stderr)
        print("  priv.pem: File chứa khóa bí mật RSA", file=sys.stderr)
        print("  cipher:   File chứa bản mã cần giải mã", file=sys.stderr)
        print("  plain:    File chứa bản rõ đầu ra", file=sys.stderr)
        sys.exit(1)
    
    priv_key_file = sys.argv[1]
    cipher_file = sys.argv[2]
    plain_file = sys.argv[3]
    
    # Đọc khóa bí mật
    print(f"Đang đọc khóa bí mật từ {priv_key_file}...")
    private_key = load_private_key(priv_key_file)
    
    print(f"Kích thước khóa: {private_key.key_size} bits")
    
    # Giải mã
    print(f"Đang giải mã {cipher_file}...")
    decrypt_file(private_key, cipher_file, plain_file)
    
    print(f"Bản rõ được lưu tại: {plain_file}")


if __name__ == "__main__":
    main()
