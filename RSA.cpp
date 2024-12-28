
#include <cstdlib>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

using namespace std;

class RSAEncryption {
public:
  RSAEncryption(int bits = 1024) {
    // Initialize OpenSSL algorithms
    OpenSSL_add_all_algorithms();

    // Create an EVP_PKEY object to hold the key pair
    pkey = EVP_PKEY_new();
    if (!pkey) {
      cerr << "Error creating EVP_PKEY object." << endl;
      exit(EXIT_FAILURE);
    }

    // Create RSA key using EVP_PKEY API
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
      cerr << "Error creating EVP_PKEY_CTX." << endl;
      exit(EXIT_FAILURE);
    }

    // Initialize the key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      cerr << "Error initializing key generation." << endl;
      exit(EXIT_FAILURE);
    }

    // Set the key size (in bits)
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
      cerr << "Error setting RSA key size." << endl;
      exit(EXIT_FAILURE);
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
      cerr << "Error generating RSA key pair." << endl;
      exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
  }

  ~RSAEncryption() {
    if (pkey) {
      EVP_PKEY_free(pkey);
    }
  }

  // Encrypt a message with the RSA public key
  int encryptMessage(const unsigned char *message, int messageLen,
                     unsigned char *encrypted) const {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
      cerr << "Error creating EVP_PKEY_CTX for encryption." << endl;
      return -1;
    }

    // Initialize the encryption operation
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
      cerr << "Error initializing encryption." << endl;
      EVP_PKEY_CTX_free(ctx);
      return -1;
    }

    size_t encryptedLen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &encryptedLen, message, messageLen) <=
        0) {
      cerr << "Error calculating encrypted message length." << endl;
      EVP_PKEY_CTX_free(ctx);
      return -1;
    }

    // Perform the encryption
    if (EVP_PKEY_encrypt(ctx, encrypted, &encryptedLen, message, messageLen) <=
        0) {
      cerr << "Error encrypting message." << endl;
      EVP_PKEY_CTX_free(ctx);
      return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return encryptedLen;
  }

  // Decrypt a message with the RSA private key
  int decryptMessage(const unsigned char *encrypted, int encryptedLen,
                     unsigned char *decrypted) const {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
      cerr << "Error creating EVP_PKEY_CTX for decryption." << endl;
      return -1;
    }

    // Initialize the decryption operation
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
      cerr << "Error initializing decryption." << endl;
      EVP_PKEY_CTX_free(ctx);
      return -1;
    }

    size_t decryptedLen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &decryptedLen, encrypted,
                         encryptedLen) <= 0) {
      cerr << "Error calculating decrypted message length." << endl;
      EVP_PKEY_CTX_free(ctx);
      return -1;
    }

    // Perform the decryption
    if (EVP_PKEY_decrypt(ctx, decrypted, &decryptedLen, encrypted,
                         encryptedLen) <= 0) {
      cerr << "Error decrypting message." << endl;
      EVP_PKEY_CTX_free(ctx);
      return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return decryptedLen;
  }

  // Print the RSA public key in PEM format
  void printPublicKey() const { PEM_write_PUBKEY(stdout, pkey); }

  // Print the RSA private key in PEM format
  void printPrivateKey() const {
    PEM_write_PrivateKey(stdout, pkey, nullptr, nullptr, 0, nullptr, nullptr);
  }

private:
  EVP_PKEY
      *pkey; // OpenSSL EVP_PKEY structure (holds both public and private keys)
};

int main() {
  // Create RSA objects for User 1 and User 2
  RSAEncryption user1(1024);
  RSAEncryption user2(1024);

  cout << "User 1 Public Key:" << endl;
  user1.printPublicKey();
  cout << "\nUser 2 Public Key:" << endl;
  user2.printPublicKey();

  // Example Message from User 1 to User 2
  const char *messageUser1 = "Hello User 2, this is User 1!";
  unsigned char encryptedUser1[256]; // Encrypted message from User 1
  unsigned char decryptedUser2[256]; // Decrypted message by User 2

  // User 1 encrypts the message with User 2's public key
  int encryptedLen1 = user2.encryptMessage(
      (unsigned char *)messageUser1, strlen(messageUser1), encryptedUser1);
  if (encryptedLen1 == -1) {
    cerr << "Error encrypting message from User 1." << endl;
    return EXIT_FAILURE;
  }
  cout << "\nUser 1 Encrypted Message (User 2's Public Key): ";
  for (int i = 0; i < encryptedLen1; i++) {
    printf("%02x", encryptedUser1[i]);
  }
  cout << endl;

  // User 2 decrypts the message with User 2's private key
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

  // User 2 encrypts the message with User 1's public key
  int encryptedLen2 = user1.encryptMessage(
      (unsigned char *)messageUser2, strlen(messageUser2), encryptedUser2);
  if (encryptedLen2 == -1) {
    cerr << "Error encrypting message from User 2." << endl;
    return EXIT_FAILURE;
  }
  cout << "\nUser 2 Encrypted Message (User 1's Public Key): ";
  for (int i = 0; i < encryptedLen2; i++) {
    printf("%02x", encryptedUser2[i]);
  }
  cout << endl;

  // User 1 decrypts the message with User 1's private key
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
