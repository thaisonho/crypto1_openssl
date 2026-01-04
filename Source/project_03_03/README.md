# Bài 3: Chữ ký số RSA

## Mô tả

Chương trình ký số và xác thực chữ ký RSA tương thích với OpenSSL.

## Cách sử dụng

### 1. Ký số
```bash
python rsa_signature.py sign priv.pem mess.txt sign.bin
```

### 2. Xác thực chữ ký
```bash
python rsa_signature.py verify pub.pem mess.txt sign.bin
```

## Demo với OpenSSL

### Tạo khóa RSA
```bash
openssl genpkey -out priv.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048
openssl pkey -in priv.pem -out pub.pem -pubout
```

## Kiểm tra tương thích

### 1. Ký bằng Python, xác thực bằng OpenSSL:
```bash
python rsa_signature.py sign priv.pem mess.txt sign.bin
openssl pkeyutl -in mess.txt -inkey pub.pem -pubin -verify -sigfile sign.bin
```

### 2. Ký bằng OpenSSL, xác thực bằng Python:
```bash
openssl pkeyutl -in mess.txt -out sign_openssl.bin -inkey priv.pem -sign
python rsa_signature.py verify pub.pem mess.txt sign_openssl.bin
```

## Ghi chú

- Chương trình sử dụng raw RSA với PKCS#1 v1.5 padding (không dùng hash)
