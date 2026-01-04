# Hướng dẫn sử dụng chương trình mã hóa và giải mã RSA

## Yêu cầu

- Python 3.6 trở lên
- Thư viện `cryptography`

## Cài đặt

Cài đặt thư viện cần thiết:

```bash
pip install cryptography
```

## Cấu trúc chương trình

- `rsa_encrypt.py`: Chương trình mã hóa RSA
- `rsa_decrypt.py`: Chương trình giải mã RSA

## Sử dụng

### 1. Tạo khóa RSA bằng OpenSSL

Trước tiên, bạn cần tạo cặp khóa RSA bằng OpenSSL:

```bash
# Tạo khóa bí mật
openssl genpkey -out priv.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048

# Tạo khóa công khai từ khóa bí mật
openssl pkey -in priv.pem -out pub.pem -pubout
```

### 2. Mã hóa bản rõ

Sử dụng chương trình `rsa_encrypt.py` để mã hóa file bản rõ:

```bash
python rsa_encrypt.py pub.pem plain.txt cipher.bin
```

Trong đó:
- `pub.pem`: File chứa khóa công khai
- `plain.txt`: File chứa bản rõ cần mã hóa
- `cipher.bin`: File chứa bản mã đầu ra

### 3. Giải mã bản mã

Sử dụng chương trình `rsa_decrypt.py` để giải mã file bản mã:

```bash
python rsa_decrypt.py priv.pem cipher.bin plain_decrypted.txt
```

Trong đó:
- `priv.pem`: File chứa khóa bí mật
- `cipher.bin`: File chứa bản mã cần giải mã
- `plain_decrypted.txt`: File chứa bản rõ đầu ra

## Kiểm tra tương thích với OpenSSL

### Mã hóa bằng chương trình tự viết, giải mã bằng OpenSSL:

```bash
# Mã hóa bằng chương trình tự viết
python rsa_encrypt.py pub.pem plain.txt cipher.bin

# Giải mã bằng OpenSSL
openssl pkeyutl -in cipher.bin -out plain_openssl.txt -inkey priv.pem -decrypt

# So sánh kết quả
diff plain.txt plain_openssl.txt
```

### Mã hóa bằng OpenSSL, giải mã bằng chương trình tự viết:

```bash
# Mã hóa bằng OpenSSL
openssl pkeyutl -in plain.txt -out cipher_openssl.bin -inkey pub.pem -pubin -encrypt

# Giải mã bằng chương trình tự viết
python rsa_decrypt.py priv.pem cipher_openssl.bin plain_decrypted.txt

# So sánh kết quả
diff plain.txt plain_decrypted.txt
```

## Lưu ý

1. Chương trình sử dụng padding PKCS#1 v1.5, tương thích với OpenSSL mặc định
2. Kích thước khối tối đa phụ thuộc vào kích thước khóa:
   - Với khóa 2048 bits: tối đa 245 bytes bản rõ mỗi khối
   - Với khóa 1024 bits: tối đa 117 bytes bản rõ mỗi khối
3. Bản rõ lớn sẽ được tự động chia thành nhiều khối
4. Bản mã luôn có kích thước bằng bội số của kích thước khóa (tính theo byte)

## Ví dụ

Tạo file bản rõ mẫu:

```bash
echo "Hello, this is a test message for RSA encryption!" > plain.txt
```

Mã hóa và giải mã:

```bash
# Mã hóa
python rsa_encrypt.py pub.pem plain.txt cipher.bin

# Giải mã
python rsa_decrypt.py priv.pem cipher.bin plain_decrypted.txt

# Kiểm tra
cat plain_decrypted.txt
```

