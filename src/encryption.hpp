extern "C" {
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
};
#include <algorithm>
#include <cmath>
#include <iostream>
#include <random>
#include <string>
#include <vector>

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
  BigInt(int n = 0) {
    if (n < 0) {
      is_negative = true;
      n = -n;
    } else {
      is_negative = false;
    }

    if (n == 0) {
      digits.push_back(0);
    } else {
      while (n > 0) {
        digits.push_back(n % 1000000000);
        n /= 1000000000;
      }
    }
  }

  BigInt(const std::string &s) {
    is_negative = false;
    digits.clear();
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

        if (carry > 0) {
          digits.push_back(carry);
        }
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

    if (num < 0)
      num = -num;

    uint64_t carry = 0;
    for (size_t i = 0; i < digits.size() || carry; i++) {
      uint64_t prod = carry;
      if (i < digits.size())
        prod += (uint64_t)digits[i] * num;

      result.digits.push_back(prod % 1000000000);
      carry = prod / 1000000000;
    }

    result.removeLeadingZeros();
    return result;
  }

  std::string toString() const {
    std::string result;
    if (is_negative)
      result = "-";

    result += std::to_string(digits.back());

    for (int i = digits.size() - 2; i >= 0; i--) {
      std::string digit = std::to_string(digits[i]);

      result += std::string(9 - digit.length(), '0') + digit;
    }

    return result;
  }
};

class RSA {
private:
  int64_t p, q;
  int64_t n;
  int64_t phi;
  int64_t d;

  int64_t e;

  bool isPrime(int64_t num) {
    if (num <= 1)
      return false;
    if (num <= 3)
      return true;
    if (num % 2 == 0 || num % 3 == 0)
      return false;

    for (int64_t i = 5; i * i <= num; i += 6) {
      if (num % i == 0 || num % (i + 2) == 0) {
        return false;
      }
    }
    return true;
  }

  int64_t generatePrime(int64_t min, int64_t max) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int64_t> dist(min, max);

    int64_t num = dist(gen);

    if (num % 2 == 0)
      num++;

    while (!isPrime(num)) {
      num += 2;
      if (num > max)
        num = min | 1;
    }

    return num;
  }

  int64_t gcd(int64_t a, int64_t b) {
    while (b != 0) {
      int64_t temp = b;
      b = a % b;
      a = temp;
    }
    return a;
  }

  int64_t modInverse(int64_t a, int64_t m) {
    int64_t m0 = m;
    int64_t y = 0, x = 1;

    if (m == 1)
      return 0;

    while (a > 1) {

      int64_t q = a / m;
      int64_t t = m;

      m = a % m;
      a = t;
      t = y;

      y = x - q * y;
      x = t;
    }

    if (x < 0)
      x += m0;

    return x;
  }

  int64_t modPow(int64_t base, int64_t exponent, int64_t modulus) {
    if (modulus == 1)
      return 0;

    int64_t result = 1;
    base = base % modulus;

    while (exponent > 0) {

      if (exponent % 2 == 1) {
        result = (result * base) % modulus;
      }

      exponent = exponent >> 1;
      base = (base * base) % modulus;
    }

    return result;
  }

public:
  RSA(int key_size = 16) {

    int64_t min_prime = 1LL << (key_size - 1);
    int64_t max_prime = (1LL << key_size) - 1;

    p = generatePrime(min_prime, max_prime);
    do {
      q = generatePrime(min_prime, max_prime);
    } while (p == q);

    n = p * q;
    phi = (p - 1) * (q - 1);

    e = 65537;

    while (gcd(e, phi) != 1) {
      e += 2;
    }

    d = modInverse(e, phi);
  }

  std::pair<int64_t, int64_t> getPublicKey() const {
    return std::make_pair(e, n);
  }

  std::pair<int64_t, int64_t> getPrivateKey() const {
    return std::make_pair(d, n);
  }

  std::vector<int64_t> encrypt(const std::string &message, int64_t public_e,
                               int64_t public_n) {
    std::vector<int64_t> encrypted;

    for (char c : message) {
      encrypted.push_back(modPow(static_cast<int64_t>(c), public_e, public_n));
    }

    return encrypted;
  }

  std::string decrypt(const std::vector<int64_t> &encrypted, int64_t private_d,
                      int64_t private_n) {
    std::string decrypted;

    for (int64_t c : encrypted) {
      decrypted.push_back(static_cast<char>(modPow(c, private_d, private_n)));
    }

    return decrypted;
  }

  void printKeyInfo() {
    std::cout << "RSA Key Information:" << std::endl;
    std::cout << "p: " << p << std::endl;
    std::cout << "q: " << q << std::endl;
    std::cout << "n (modulus): " << n << std::endl;
    std::cout << "phi: " << phi << std::endl;
    std::cout << "e (public exponent): " << e << std::endl;
    std::cout << "d (private exponent): " << d << std::endl;
  }
};

class Client {
private:
  std::pair<int64_t, int64_t> publicKey;
  std::pair<int64_t, int64_t> privateKey;
  RSA rsa;

public:
  Client() : rsa(16) {
    publicKey = rsa.getPublicKey();
    privateKey = rsa.getPrivateKey();
  }

  std::pair<int64_t, int64_t> getPublicKey() const { return publicKey; }

  std::vector<int64_t>
  encryptMessage(const std::string &message,
                 const std::pair<int64_t, int64_t> &receiverPublicKey) {
    return rsa.encrypt(message, receiverPublicKey.first,
                       receiverPublicKey.second);
  }

  std::string decryptMessage(const std::vector<int64_t> &encryptedMessage) {
    return rsa.decrypt(encryptedMessage, privateKey.first, privateKey.second);
  }
};

void Checking_if_its_works() {

  Client alice;
  Client bob;

  std::string message = "Hello Bob, this is a secret message!";
  std::cout << "Original message: " << message << std::endl;

  auto bobPublicKey = bob.getPublicKey();
  auto encrypted = alice.encryptMessage(message, bobPublicKey);

  std::cout << "Encrypted message (numerical representation): ";
  for (size_t i = 0; i < 5 && i < encrypted.size(); i++) {
    std::cout << encrypted[i] << " ";
  }
  std::cout << "..." << std::endl;

  auto decrypted = bob.decryptMessage(encrypted);

  std::cout << "Decrypted message: " << decrypted << std::endl;
}

int main() {
  std::cout << "RSA Encryption Example" << std::endl;
  std::cout << "======================" << std::endl;

  std::cout << "Testing BigInt..." << std::endl;
  BigInt a("123456789");
  BigInt b = a * 2;
  std::cout << "a = " << a.toString() << std::endl;
  std::cout << "a * 2 = " << b.toString() << std::endl;

  RSA rsa(16);
  rsa.printKeyInfo();

  std::cout << "\nSimulating secure communication between two clients:"
            << std::endl;
  Checking_if_its_works();

  return 0;
}

class AES {
private:
  std::vector<unsigned char> key; // 16 bytes for AES-128
  std::vector<unsigned char> iv;  // 16 bytes for initialization vector

  // Print OpenSSL errors
  void handleErrors() {
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("OpenSSL error occurred");
  }

public:
  // Constructor with key and IV generation
  AES() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    generateKeyAndIV();
  }

  // Constructor with specified key and IV
  AES(const std::vector<unsigned char> &keyInput,
      const std::vector<unsigned char> &ivInput) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    setKey(keyInput);
    setIV(ivInput);
  }

  // Cleanup in destructor
  ~AES() {
    EVP_cleanup();
    ERR_free_strings();
  }

  // Generate random key and IV
  void generateKeyAndIV() {
    key.resize(16); // AES-128 uses 16-byte keys
    iv.resize(16);  // AES uses 16-byte IV

    // Use OpenSSL's secure random number generator
    if (RAND_bytes(key.data(), key.size()) != 1) {
      handleErrors();
    }
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
      handleErrors();
    }
  }

  // Getters for key and IV
  std::vector<unsigned char> getKey() const { return key; }
  std::vector<unsigned char> getIV() const { return iv; }

  // Set key
  void setKey(const std::vector<unsigned char> &newKey) {
    if (newKey.size() != 16) {
      throw std::invalid_argument("AES-128 requires a 16-byte key");
    }
    key = newKey;
  }

  // Set IV
  void setIV(const std::vector<unsigned char> &newIV) {
    if (newIV.size() != 16) {
      throw std::invalid_argument("AES requires a 16-byte IV");
    }
    iv = newIV;
  }

  // Encrypt using AES-128 in CBC mode
  std::vector<unsigned char> encrypt(const std::string &plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      handleErrors();
    }

    // Initialize the encryption operation with AES-128-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(),
                           iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }

    // Prepare output buffer
    std::vector<unsigned char> ciphertext(
        plaintext.size() + AES_BLOCK_SIZE); // Add space for potential padding
    int len = 0, ciphertext_len = 0;

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(
            ctx, ciphertext.data(), &len,
            reinterpret_cast<const unsigned char *>(plaintext.c_str()),
            plaintext.size()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }
    ciphertext_len = len;

    // Finalize the encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Resize to actual ciphertext length
    ciphertext.resize(ciphertext_len);
    return ciphertext;
  }

  // Decrypt using AES-128 in CBC mode
  std::string decrypt(const std::vector<unsigned char> &ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      handleErrors();
    }

    // Initialize the decryption operation with AES-128-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(),
                           iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }

    // Prepare output buffer
    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int len = 0, plaintext_len = 0;

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                          ciphertext.size()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }
    plaintext_len = len;

    // Finalize the decryption (handle padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      handleErrors();
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Convert to string and return
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
  }

  // Utility function to convert bytes to hex string
  static std::string bytesToHexString(const std::vector<unsigned char> &bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (auto byte : bytes) {
      ss << std::setw(2) << static_cast<int>(byte);
    }

    return ss.str();
  }

  // Utility function to convert hex string to bytes
  static std::vector<unsigned char>
  hexStringToBytes(const std::string &hexString) {
    std::vector<unsigned char> bytes;

    for (size_t i = 0; i < hexString.length(); i += 2) {
      std::string byteString = hexString.substr(i, 2);
      unsigned char byte =
          static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
      bytes.push_back(byte);
    }

    return bytes;
  }
}
