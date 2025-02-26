#ifndef CRYPTO_TOOLS_HPP
#define CRYPTO_TOOLS_HPP

extern "C" {
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
};

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class AES {
private:
  std::vector<unsigned char> key;
  std::vector<unsigned char> iv;

  void handleErrors() {
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("OpenSSL error occurred");
  }

public:
  AES() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    generateKeyAndIV();
  }

  AES(const std::vector<unsigned char> &keyInput,
      const std::vector<unsigned char> &ivInput) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    setKey(keyInput);
    setIV(ivInput);
  }

  ~AES() {
    EVP_cleanup();
    ERR_free_strings();
  }

  void generateKeyAndIV() {
    key.resize(32); // AES-256 requires 32-byte key
    iv.resize(16);  // IV remains 16 bytes for CBC mode

    if (RAND_bytes(key.data(), key.size()) != 1)
      handleErrors();
    if (RAND_bytes(iv.data(), iv.size()) != 1)
      handleErrors();
  }

  std::vector<unsigned char> getKey() const { return key; }
  std::vector<unsigned char> getIV() const { return iv; }

  void setKey(const std::vector<unsigned char> &newKey) {
    if (newKey.size() != 32) {
      throw std::invalid_argument("AES-256 requires a 32-byte key");
    }
    key = newKey;
  }

  void setIV(const std::vector<unsigned char> &newIV) {
    if (newIV.size() != 16) {
      throw std::invalid_argument("AES requires a 16-byte IV");
    }
    iv = newIV;
  }

  std::vector<unsigned char> encrypt(const std::string &plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
      handleErrors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(),
                           iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(
            ctx, ciphertext.data(), &len,
            reinterpret_cast<const unsigned char *>(plaintext.c_str()),
            plaintext.size()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
  }

  std::string decrypt(const std::vector<unsigned char> &ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
      handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(),
                           iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                          ciphertext.size()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
  }

  static std::string bytesToHexString(const std::vector<unsigned char> &bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto byte : bytes) {
      ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
  }

  static std::vector<unsigned char>
  hexStringToBytes(const std::string &hexString) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hexString.length(); i += 2) {
      std::string byteString = hexString.substr(i, 2);
      bytes.push_back(
          static_cast<unsigned char>(std::stoi(byteString, nullptr, 16)));
    }
    return bytes;
  }
};

class BigInt {
private:
  std::vector<uint32_t> digits;
  bool is_negative;

  void removeLeadingZeros() {
    while (digits.size() > 1 && digits.back() == 0) {
      digits.pop_back();
    }
  }

public:
  BigInt(int n = 0) : is_negative(n < 0) {
    if (n < 0)
      n = -n;
    if (n == 0)
      digits.push_back(0);
    while (n > 0) {
      digits.push_back(n % 1000000000);
      n /= 1000000000;
    }
  }

  BigInt(const std::string &s) : is_negative(false) {
    digits.push_back(0);
    for (char c : s) {
      if (c >= '0' && c <= '9') {
        uint64_t carry = c - '0';
        for (size_t i = 0; i < digits.size(); i++) {
          uint64_t current = digits[i];
          current = current * 10 + carry;
          digits[i] = current % 1000000000;
          carry = current / 1000000000;
        }
        if (carry > 0)
          digits.push_back(carry);
      }
    }
    removeLeadingZeros();
  }

  BigInt operator+(const BigInt &other) const {
    BigInt result;
    result.digits.clear();
    size_t n = std::max(digits.size(), other.digits.size());
    uint64_t carry = 0;

    for (size_t i = 0; i < n || carry; i++) {
      uint64_t sum = carry;
      if (i < digits.size())
        sum += digits[i];
      if (i < other.digits.size())
        sum += other.digits[i];
      result.digits.push_back(sum % 1000000000);
      carry = sum / 1000000000;
    }
    result.removeLeadingZeros();
    return result;
  }

  BigInt operator*(int num) const {
    if (num == 0)
      return BigInt(0);
    BigInt result;
    result.digits.clear();
    result.is_negative = is_negative != (num < 0);
    num = std::abs(num);

    uint64_t carry = 0;
    for (size_t i = 0; i < digits.size() || carry; i++) {
      uint64_t prod = carry;
      if (i < digits.size())
        prod += static_cast<uint64_t>(digits[i]) * num;
      result.digits.push_back(prod % 1000000000);
      carry = prod / 1000000000;
    }
    result.removeLeadingZeros();
    return result;
  }

  std::string toString() const {
    if (digits.empty())
      return "0";
    std::string result = is_negative ? "-" : "";
    result += std::to_string(digits.back());
    for (int i = static_cast<int>(digits.size()) - 2; i >= 0; i--) {
      std::string part = std::to_string(digits[i]);
      result += std::string(9 - part.length(), '0') + part;
    }
    return result;
  }
};

class RSA {
private:
  int64_t p, q, n, phi, d, e;

  bool isPrime(int64_t num) {
    if (num <= 1)
      return false;
    if (num <= 3)
      return true;
    if (num % 2 == 0 || num % 3 == 0)
      return false;
    for (int64_t i = 5; i * i <= num; i += 6) {
      if (num % i == 0 || num % (i + 2) == 0)
        return false;
    }
    return true;
  }

  int64_t generatePrime(int64_t min, int64_t max) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int64_t> dist(min, max);
    int64_t num = dist(gen) | 1;
    while (!isPrime(num))
      num += 2;
    return num;
  }

  int64_t gcd(int64_t a, int64_t b) {
    while (b != 0)
      std::swap(a %= b, b);
    return a;
  }

  int64_t modInverse(int64_t a, int64_t m) {
    int64_t m0 = m, y = 0, x = 1;
    if (m == 1)
      return 0;
    while (a > 1) {
      int64_t q = a / m;
      std::swap(m, a %= m);
      std::swap(x -= q * y, y);
    }
    return x < 0 ? x + m0 : x;
  }

  int64_t modPow(int64_t base, int64_t exp, int64_t mod) {
    int64_t result = 1;
    base %= mod;
    while (exp > 0) {
      if (exp & 1)
        result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1;
    }
    return result;
  }

public:
  RSA(int key_size = 16) {
    int64_t min = 1LL << (key_size - 1);
    int64_t max = (1LL << key_size) - 1;
    p = generatePrime(min, max);
    do
      q = generatePrime(min, max);
    while (p == q);
    n = p * q;
    phi = (p - 1) * (q - 1);
    e = 65537;
    while (gcd(e, phi) != 1)
      e += 2;
    d = modInverse(e, phi);
  }

  std::pair<int64_t, int64_t> getPublicKey() const { return {e, n}; }
  std::pair<int64_t, int64_t> getPrivateKey() const { return {d, n}; }

  std::vector<int64_t> encrypt(const std::string &msg, int64_t e, int64_t n) {
    std::vector<int64_t> cipher;
    for (char c : msg)
      cipher.push_back(modPow(c, e, n));
    return cipher;
  }

  std::string decrypt(const std::vector<int64_t> &cipher, int64_t d,
                      int64_t n) {
    std::string msg;
    for (int64_t c : cipher)
      msg += static_cast<char>(modPow(c, d, n));
    return msg;
  }

  void printKeyInfo() const {
    std::cout << "RSA Key Info:\n"
              << "p: " << p << "\nq: " << q << "\nn: " << n << "\nphi: " << phi
              << "\ne: " << e << "\nd: " << d << "\n";
  }
};

class Client {
private:
  RSA rsa;
  std::pair<int64_t, int64_t> pubKey, privKey;

public:
  Client() : rsa(16) {
    pubKey = rsa.getPublicKey();
    privKey = rsa.getPrivateKey();
  }

  std::pair<int64_t, int64_t> getPublicKey() const { return pubKey; }

  std::vector<int64_t>
  encryptMessage(const std::string &msg,
                 const std::pair<int64_t, int64_t> &recvPub) {
    return rsa.encrypt(msg, recvPub.first, recvPub.second);
  }

  std::string decryptMessage(const std::vector<int64_t> &cipher) {
    return rsa.decrypt(cipher, privKey.first, privKey.second);
  }
};

#endif // CRYPTO_TOOLS_HPP
