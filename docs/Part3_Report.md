# Báo cáo Phần 3: Mã hóa khóa công khai RSA của OpenSSL

## 3.2.1 Báo cáo về mã hóa và giải mã RSA của OpenSSL

### Tổng quan về quá trình mã hóa và giải mã RSA

RSA (Rivest-Shamir-Adleman) là một hệ mật mã khóa công khai sử dụng hai khóa: khóa công khai để mã hóa và khóa bí mật để giải mã. OpenSSL sử dụng định dạng PEM (Privacy-Enhanced Mail) để lưu trữ các khóa RSA, được mã hóa bằng Base64 và chứa trong các tệp có định dạng `.pem`.

### Cấu trúc tệp khóa

**Tệp khóa công khai (`pub.pem`):**
- Định dạng: PEM (Base64 encoded)
- Chứa: Modulus (N) và Public Exponent (e)
- Định dạng ASN.1: SubjectPublicKeyInfo

**Tệp khóa bí mật (`priv.pem`):**
- Định dạng: PEM (Base64 encoded)
- Chứa: Modulus (N), Public Exponent (e), Private Exponent (d), Prime factors (p, q), và các tham số khác
- Định dạng ASN.1: PrivateKeyInfo hoặc RSAPrivateKey

### Quy trình mã hóa RSA với OpenSSL

**Bước 1: Đọc và phân tích khóa công khai**

```
1. Đọc tệp pub.pem
2. Loại bỏ header "-----BEGIN PUBLIC KEY-----" và footer "-----END PUBLIC KEY-----"
3. Giải mã Base64 để thu được dữ liệu binary
4. Parse cấu trúc ASN.1 để trích xuất:
   - Modulus N (số nguyên lớn)
   - Public Exponent e (thường là 65537)
```

**Bước 2: Xử lý bản rõ**

```
1. Đọc toàn bộ nội dung tệp plain
2. Kiểm tra kích thước bản rõ:
   - Nếu kích thước > (kích thước khóa - padding overhead):
     → Chia bản rõ thành các khối nhỏ hơn
   - Mỗi khối phải nhỏ hơn kích thước khóa (tính theo byte)
3. Với RSA, kích thước khối tối đa = (key_size / 8) - padding_size
   - Với PKCS#1 v1.5 padding: padding_size = 11 bytes
   - Với OAEP padding: padding_size phụ thuộc vào hash function
```

**Bước 3: Mã hóa từng khối**

```
Với mỗi khối M của bản rõ:
1. Áp dụng padding scheme (PKCS#1 v1.5 hoặc OAEP)
2. Chuyển đổi khối đã padding thành số nguyên m
3. Thực hiện phép tính: c = m^e mod N
4. Chuyển đổi c thành dạng binary
5. Ghi vào tệp cipher
```

**Mã giả cho quá trình mã hóa:**

```pseudocode
FUNCTION RSA_ENCRYPT(pub_key_file, plain_file, cipher_file):
    // Đọc khóa công khai
    public_key = READ_PUBLIC_KEY(pub_key_file)
    N = public_key.modulus
    e = public_key.exponent
    key_size = BIT_LENGTH(N)
    block_size = (key_size / 8) - 11  // PKCS#1 v1.5 padding
    
    // Đọc bản rõ
    plaintext = READ_FILE(plain_file)
    
    // Chia thành các khối
    blocks = SPLIT_INTO_BLOCKS(plaintext, block_size)
    
    // Mã hóa từng khối
    ciphertext = []
    FOR EACH block IN blocks:
        // Chuyển block thành số nguyên
        m = BYTES_TO_INTEGER(block)
        
        // Áp dụng padding PKCS#1 v1.5
        padded_block = PKCS1_PADDING(block, key_size)
        m_padded = BYTES_TO_INTEGER(padded_block)
        
        // Mã hóa: c = m^e mod N
        c = MODULAR_POWER(m_padded, e, N)
        
        // Chuyển về dạng bytes
        cipher_block = INTEGER_TO_BYTES(c, key_size / 8)
        ciphertext.APPEND(cipher_block)
    
    // Ghi bản mã
    WRITE_FILE(cipher_file, CONCATENATE(ciphertext))
END FUNCTION
```

### Quy trình giải mã RSA với OpenSSL

**Bước 1: Đọc và phân tích khóa bí mật**

```
1. Đọc tệp priv.pem
2. Loại bỏ header "-----BEGIN PRIVATE KEY-----" và footer "-----END PRIVATE KEY-----"
3. Giải mã Base64 để thu được dữ liệu binary
4. Parse cấu trúc ASN.1 để trích xuất:
   - Modulus N
   - Private Exponent d
   - Prime factors p, q (nếu có, để tối ưu hóa)
```

**Bước 2: Đọc bản mã**

```
1. Đọc toàn bộ nội dung tệp cipher
2. Chia bản mã thành các khối:
   - Mỗi khối có kích thước = key_size / 8 bytes
   - Số khối = length(cipher) / (key_size / 8)
```

**Bước 3: Giải mã từng khối**

```
Với mỗi khối C của bản mã:
1. Chuyển đổi khối C thành số nguyên c
2. Thực hiện phép tính: m = c^d mod N
3. Chuyển đổi m thành dạng binary
4. Loại bỏ padding để thu được bản rõ gốc
5. Ghi vào tệp plain
```

**Mã giả cho quá trình giải mã:**

```pseudocode
FUNCTION RSA_DECRYPT(priv_key_file, cipher_file, plain_file):
    // Đọc khóa bí mật
    private_key = READ_PRIVATE_KEY(priv_key_file)
    N = private_key.modulus
    d = private_key.private_exponent
    key_size = BIT_LENGTH(N)
    block_size = key_size / 8
    
    // Đọc bản mã
    ciphertext = READ_FILE(cipher_file)
    
    // Chia thành các khối
    blocks = SPLIT_INTO_BLOCKS(ciphertext, block_size)
    
    // Giải mã từng khối
    plaintext = []
    FOR EACH block IN blocks:
        // Chuyển block thành số nguyên
        c = BYTES_TO_INTEGER(block)
        
        // Giải mã: m = c^d mod N
        m = MODULAR_POWER(c, d, N)
        
        // Chuyển về dạng bytes
        m_bytes = INTEGER_TO_BYTES(m, block_size)
        
        // Loại bỏ padding PKCS#1 v1.5
        plain_block = REMOVE_PKCS1_PADDING(m_bytes)
        plaintext.APPEND(plain_block)
    
    // Ghi bản rõ
    WRITE_FILE(plain_file, CONCATENATE(plaintext))
END FUNCTION
```

### Sơ đồ quy trình mã hóa

```
┌─────────────┐
│  pub.pem    │
│  (Khóa CK)  │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│ Parse PEM format    │
│ Extract N, e         │
└──────┬──────────────┘
       │
       ▼
┌─────────────┐      ┌─────────────┐
│  plain      │─────▶│ Chia khối   │
│  (Bản rõ)   │      │ (nếu cần)   │
└─────────────┘      └──────┬──────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ Áp dụng       │
                    │ PKCS#1 padding│
                    └──────┬────────┘
                           │
                           ▼
                    ┌───────────────┐
                    │ c = m^e mod N │
                    │ (Mã hóa)      │
                    └──────┬────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  cipher     │
                    │  (Bản mã)   │
                    └─────────────┘
```

### Sơ đồ quy trình giải mã

```
┌─────────────┐
│  priv.pem   │
│  (Khóa BM)  │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│ Parse PEM format    │
│ Extract N, d        │
└──────┬──────────────┘
       │
       ▼
┌─────────────┐      ┌─────────────┐
│  cipher     │─────▶│ Chia khối   │
│  (Bản mã)   │      │ (theo kích  │
└─────────────┘      │  thước khóa)│
                     └──────┬──────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ m = c^d mod N │
                    │ (Giải mã)     │
                    └──────┬────────┘
                           │
                           ▼
                    ┌───────────────┐
                    │ Loại bỏ       │
                    │ PKCS#1 padding│
                    └──────┬────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  plain    │
                    │  (Bản rõ)  │
                    └─────────────┘
```

### Chi tiết kỹ thuật

**1. Padding Scheme (PKCS#1 v1.5):**

```
Format: 00 || 02 || PS || 00 || M

Trong đó:
- 00: Byte đánh dấu
- 02: Loại padding (02 cho encryption)
- PS: Padding String (ít nhất 8 bytes ngẫu nhiên khác 0)
- 00: Byte phân cách
- M: Bản rõ gốc

Tổng kích thước = key_size / 8 bytes
```

**2. Modular Exponentiation:**

OpenSSL sử dụng thuật toán lũy thừa nhanh (Fast Exponentiation) để tính `m^e mod N`:

```
Thuật toán:
result = 1
base = m mod N
WHILE e > 0:
    IF e is odd:
        result = (result * base) mod N
    base = (base * base) mod N
    e = e / 2
RETURN result
```

**3. Xử lý khối lớn:**

Khi bản rõ lớn hơn kích thước khối tối đa, OpenSSL:
- Chia bản rõ thành nhiều khối
- Mã hóa từng khối độc lập
- Nối các bản mã lại với nhau

**4. Tối ưu hóa giải mã (Chinese Remainder Theorem):**

Khi có p và q, OpenSSL có thể tối ưu hóa:
```
m1 = c^d mod p
m2 = c^d mod q
m = CRT(m1, m2, p, q)
```

### Tương thích giữa OpenSSL và chương trình tự viết

Để đảm bảo tương thích:
1. Sử dụng cùng padding scheme (PKCS#1 v1.5)
2. Sử dụng cùng định dạng PEM để đọc khóa
3. Xử lý endianness đúng cách (big-endian)
4. Đảm bảo kích thước khối phù hợp với kích thước khóa

## 3.2.2 Chương trình mã hóa

**Thông tin mã nguồn:**
- **Ngôn ngữ lập trình:** Python 3.6+
- **Thư viện cần cài đặt:**
  ```bash
  pip install cryptography
  ```
- **Cách biên dịch:** Không cần biên dịch (Python là ngôn ngữ thông dịch)
- **Cách chạy:**
  ```bash
  python rsa_encrypt.py <pub.pem> <plain> <cipher>
  ```
  Ví dụ:
  ```bash
  python rsa_encrypt.py pub.pem plain.txt cipher.bin
  ```

**Mô tả chương trình:**
Chương trình `rsa_encrypt.py` đọc khóa công khai từ tệp `pub.pem`, đọc bản rõ từ tệp `plain`, thực hiện mã hóa RSA và ghi kết quả vào tệp `cipher`. Chương trình sử dụng thư viện `cryptography` để xử lý định dạng PEM và thực hiện mã hóa RSA với padding PKCS#1 v1.5, đảm bảo tương thích hoàn toàn với OpenSSL.

**Tính năng:**
- Tự động chia bản rõ lớn thành nhiều khối
- Sử dụng padding PKCS#1 v1.5 (tương thích với OpenSSL)
- Hiển thị thông tin về kích thước bản rõ, bản mã và số khối
- Xử lý lỗi đầy đủ

**Mã nguồn:** Xem file `Source/rsa_encrypt.py`

## 3.2.3 Chương trình giải mã

**Thông tin mã nguồn:**
- **Ngôn ngữ lập trình:** Python 3.6+
- **Thư viện cần cài đặt:**
  ```bash
  pip install cryptography
  ```
- **Cách biên dịch:** Không cần biên dịch (Python là ngôn ngữ thông dịch)
- **Cách chạy:**
  ```bash
  python rsa_decrypt.py <priv.pem> <cipher> <plain>
  ```
  Ví dụ:
  ```bash
  python rsa_decrypt.py priv.pem cipher.bin plain_decrypted.txt
  ```

**Mô tả chương trình:**
Chương trình `rsa_decrypt.py` đọc khóa bí mật từ tệp `priv.pem`, đọc bản mã từ tệp `cipher`, thực hiện giải mã RSA và ghi bản rõ vào tệp `plain`. Chương trình có thể giải mã các bản mã được tạo bởi OpenSSL hoặc chương trình mã hóa tự viết, đảm bảo tương thích hoàn toàn.

**Tính năng:**
- Tự động xử lý nhiều khối bản mã
- Sử dụng padding PKCS#1 v1.5 (tương thích với OpenSSL)
- Hiển thị thông tin về kích thước bản mã, bản rõ và số khối
- Kiểm tra tính hợp lệ của kích thước bản mã
- Xử lý lỗi đầy đủ

**Mã nguồn:** Xem file `Source/rsa_decrypt.py`

## 3.2.4 Video demo

**Thông tin video:**
- **Nơi tải lên:** [URL video sẽ được cập nhật]
- **Nội dung demo:**
  1. Tạo khóa RSA bằng OpenSSL
  2. Mã hóa bản rõ bằng chương trình tự viết
  3. Giải mã bằng OpenSSL để xác minh
  4. Mã hóa bằng OpenSSL
  5. Giải mã bằng chương trình tự viết để xác minh

