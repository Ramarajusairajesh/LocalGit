#include <cstdlib>
#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

// Define AES Block size (16 bytes for AES)
#define AES_BLOCK_SIZE 16 // AES block size is 16 bytes (128 bits)

class AESEncryption {
public:
  AESEncryption() {
    // Generate a random AES key (256-bit) and IV (128-bit)
    if (!RAND_bytes(key, AES_KEYLEN) || !RAND_bytes(iv, AES_BLOCK_SIZE)) {
      cerr << "Error generating random key or IV." << endl;
      exit(EXIT_FAILURE);
    }
  }

  ~AESEncryption() {}

  // Encrypt a message using AES (CBC mode)
  int encryptMessage(const unsigned char *message, int messageLen,
                     unsigned char *encrypted) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      cerr << "Error creating EVP context." << endl;
      return -1;
    }

    // Initialize the encryption context for AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
      cerr << "Error initializing encryption." << endl;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

    // Padding to be a multiple of AES_BLOCK_SIZE (16 bytes)
    int padding = AES_BLOCK_SIZE - messageLen % AES_BLOCK_SIZE;
    int encryptedLen = messageLen + padding;
    unsigned char *paddedMessage = new unsigned char[encryptedLen];

    // Padding the message to be a multiple of AES_BLOCK_SIZE (PKCS7 padding)
    memcpy(paddedMessage, message, messageLen);
    memset(paddedMessage + messageLen, padding, padding);

    int len;
    if (EVP_EncryptUpdate(ctx, encrypted, &len, paddedMessage, encryptedLen) !=
        1) {
      cerr << "Error encrypting message." << endl;
      delete[] paddedMessage;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

    int finalLen;
    if (EVP_EncryptFinal_ex(ctx, encrypted + len, &finalLen) != 1) {
      cerr << "Error finalizing encryption." << endl;
      delete[] paddedMessage;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

    encryptedLen = len + finalLen;

    delete[] paddedMessage;
    EVP_CIPHER_CTX_free(ctx);
    return encryptedLen;
  }

  // Decrypt a message using AES (CBC mode)
  int decryptMessage(const unsigned char *encrypted, int encryptedLen,
                     unsigned char *decrypted) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      cerr << "Error creating EVP context." << endl;
      return -1;
    }

    // Initialize the decryption context for AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
      cerr << "Error initializing decryption." << endl;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, decrypted, &len, encrypted, encryptedLen) != 1) {
      cerr << "Error decrypting message." << endl;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

    int finalLen;
    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &finalLen) != 1) {
      cerr << "Error finalizing decryption." << endl;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

    int decryptedLen = len + finalLen;

    // Remove padding (PKCS7 padding)
    int padding = decrypted[decryptedLen - 1];
    decryptedLen -= padding;

    EVP_CIPHER_CTX_free(ctx);
    return decryptedLen;
  }

  // Print the AES key (in hexadecimal)
  void printKey() const {
    cout << "AES Key (Hex): ";
    for (int i = 0; i < AES_KEYLEN; ++i) {
      printf("%02x", key[i]);
    }
    cout << endl;
  }

  // Print the IV (in hexadecimal)
  void printIV() const {
    cout << "AES IV (Hex): ";
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
      printf("%02x", iv[i]);
    }
    cout << endl;
  }

private:
  static const int AES_KEYLEN = 32; // AES 256-bit key
  unsigned char key[AES_KEYLEN];    // AES key
  unsigned char iv[AES_BLOCK_SIZE]; // AES IV (block size = 16 bytes)
};

int main_function() {
  // Create AES objects for User 1 and User 2
  AESEncryption user1;
  AESEncryption user2;

  // Example Message from User 1 to User 2
  const char *messageUser1 = "Hello User 2, this is User 1!";
  unsigned char encryptedUser1[256]; // Encrypted message from User 1
  unsigned char decryptedUser2[256]; // Decrypted message by User 2

  // User 1 encrypts the message
  int encryptedLen1 = user2.encryptMessage(
      (unsigned char *)messageUser1, strlen(messageUser1), encryptedUser1);
  if (encryptedLen1 == -1) {
    cerr << "Error encrypting message from User 1." << endl;
    return EXIT_FAILURE;
  }
  cout << "\nUser 1 Encrypted Message (AES Encryption): ";
  for (int i = 0; i < encryptedLen1; i++) {
    printf("%02x", encryptedUser1[i]);
  }
  cout << endl;

  // User 2 decrypts the message
  int decryptedLen2 =
      user2.decryptMessage(encryptedUser1, encryptedLen1, decryptedUser2);
  if (decryptedLen2 == -1) {
    cerr << "Error decrypting message by User 2." << endl;
    return EXIT_FAILURE;
  }
  decryptedUser2[decryptedLen2] = '\0'; // Null-terminate the decrypted string
  cout << "\nUser 2 Decrypted Message: " << decryptedUser2 << endl;

  // Now, User 2 replies to User 1
  const char *messageUser2 = "Hello User 1, this is User 2!";
  unsigned char encryptedUser2[256]; // Encrypted message from User 2
  unsigned char decryptedUser1[256]; // Decrypted message by User 1

  // User 2 encrypts the message
  int encryptedLen2 = user1.encryptMessage(
      (unsigned char *)messageUser2, strlen(messageUser2), encryptedUser2);
  if (encryptedLen2 == -1) {
    cerr << "Error encrypting message from User 2." << endl;
    return EXIT_FAILURE;
  }
  cout << "\nUser 2 Encrypted Message (AES Encryption): ";
  for (int i = 0; i < encryptedLen2; i++) {
    printf("%02x", encryptedUser2[i]);
  }
  cout << endl;

  // User 1 decrypts the message
  int decryptedLen1 =
      user1.decryptMessage(encryptedUser2, encryptedLen2, decryptedUser1);
  if (decryptedLen1 == -1) {
    cerr << "Error decrypting message by User 1." << endl;
    return EXIT_FAILURE;
  }
  decryptedUser1[decryptedLen1] = '\0'; // Null-terminate the decrypted string
  cout << "\nUser 1 Decrypted Message: " << decryptedUser1 << endl;

  return EXIT_SUCCESS;
}
