# Bài 1: Đọc và Kiểm tra Khóa RSA

## Mô tả

Chương trình đọc và kiểm tra tính hợp lệ của khóa RSA từ file PEM.

## Cách sử dụng

### Đọc private key
```bash
python rsa_key_parser.py priv.pem
```

### Đọc cả private key và public key
```bash
python rsa_key_parser.py priv.pem pub.pem
```

## Thông tin hiển thị

- **Key Components**: n, e, d, p, q, dP, dQ, qInv
- **Key Validation**: Kiểm tra các điều kiện hợp lệ của khóa RSA

## Demo với OpenSSL

### Tạo khóa RSA
```bash
# Tạo khóa bí mật
openssl genpkey -out priv.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048

# Tạo khóa công khai từ khóa bí mật
openssl pkey -in priv.pem -out pub.pem -pubout
```

### So sánh với OpenSSL
```bash
openssl pkey -in priv.pem -text -noout
```
