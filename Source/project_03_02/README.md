# Bài 2: Mã hóa và Giải mã RSA với OpenSSL

## Mô tả

Phần này chứa các chương trình mã hóa và giải mã RSA tương thích với OpenSSL.

## Cách sử dụng

### 1. Mã hóa RSA
Ví dụ:
```bash
python rsa_encrypt.py pub.pem plain cipher_output
```

### 2. Giải mã RSA
Ví dụ:
```bash
python rsa_decrypt.py priv.pem cipher plain_output
```

## Demo với OpenSSL

### Tạo khóa RSA
```bash
# Tạo khóa bí mật
openssl genpkey -out priv.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048

# Tạo khóa công khai từ khóa bí mật
openssl pkey -in priv.pem -out pub.pem -pubout
```

## Kiểm tra tương thích

### 1. Mã hóa bằng Python, giải mã bằng OpenSSL:
```bash
python rsa_encrypt.py pub.pem plain cipher_py
openssl pkeyutl -in cipher_py -out plain_check -inkey priv.pem -decrypt
cat plain_check
```

### 2. Mã hóa bằng OpenSSL, giải mã bằng Python:
```bash
openssl pkeyutl -in plain -out cipher_openssl -inkey pub.pem -pubin -encrypt
python rsa_decrypt.py priv.pem cipher_openssl plain_check
cat plain_check
```

## Ghi chú

- Chương trình sử dụng padding PKCS#1 v1.5 để tương thích với OpenSSL mặc định
- Khóa RSA 2048-bit có thể mã hóa tối đa 245 bytes (256 - 11 bytes overhead của PKCS#1 v1.5)
- Chương trình hỗ trợ chia khối cho bản rõ lớn hơn giới hạn
