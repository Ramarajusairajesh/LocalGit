// client.cpp
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#define PORT 8080
#define BUFFER_SIZE 4096
#define AES_KEY_SIZE 32

class SecureFileClient {
private:
  int sock;
  struct sockaddr_in serv_addr;
  std::vector<unsigned char> aes_key;

  void initializeSocket(const char *server_ip) {
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      throw std::runtime_error("Socket creation failed");
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
      throw std::runtime_error("Invalid address");
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      throw std::runtime_error("Connection failed");
    }
  }

  void generateAESKey() {
    aes_key.resize(AES_KEY_SIZE);
    if (!RAND_bytes(aes_key.data(), AES_KEY_SIZE)) {
      throw std::runtime_error("Failed to generate AES key");
    }
  }

  std::vector<unsigned char> readFile(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
      throw std::runtime_error("Cannot open file: " + filename);
    }

    auto size = file.tellg();
    file.seekg(0);
    std::vector<unsigned char> data(size);
    file.read((char *)data.data(), size);
    return data;
  }

  std::vector<unsigned char>
  encryptWithRSA(EVP_PKEY *pub_key, const std::vector<unsigned char> &data) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    EVP_PKEY_encrypt_init(ctx);

    size_t encrypted_len;
    EVP_PKEY_encrypt(ctx, nullptr, &encrypted_len, data.data(), data.size());

    std::vector<unsigned char> encrypted(encrypted_len);
    EVP_PKEY_encrypt(ctx, encrypted.data(), &encrypted_len, data.data(),
                     data.size());

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
  }

  std::vector<unsigned char>
  encryptWithAES(const std::vector<unsigned char> &data) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), 16);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(),
                       iv.data());

    std::vector<unsigned char> encrypted;
    encrypted.insert(encrypted.end(), iv.begin(), iv.end());

    std::vector<unsigned char> buffer(data.size() + EVP_MAX_BLOCK_LENGTH);
    int update_len, final_len;

    EVP_EncryptUpdate(ctx, buffer.data(), &update_len, data.data(),
                      data.size());
    encrypted.insert(encrypted.end(), buffer.begin(),
                     buffer.begin() + update_len);

    EVP_EncryptFinal_ex(ctx, buffer.data(), &final_len);
    encrypted.insert(encrypted.end(), buffer.begin(),
                     buffer.begin() + final_len);

    EVP_CIPHER_CTX_free(ctx);
    return encrypted;
  }

public:
  SecureFileClient(const char *server_ip) {
    OpenSSL_add_all_algorithms();
    initializeSocket(server_ip);
    generateAESKey();
  }

  ~SecureFileClient() { close(sock); }

  void sendFile(const std::string &filename) {
    // Receive server's public key
    char pub_key_buf[4096];
    int bytes = recv(sock, pub_key_buf, sizeof(pub_key_buf), 0);

    BIO *bio = BIO_new_mem_buf(pub_key_buf, bytes);
    EVP_PKEY *server_public_key =
        PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    // Encrypt AES key with server's public key
    auto encrypted_aes_key = encryptWithRSA(server_public_key, aes_key);
    send(sock, encrypted_aes_key.data(), encrypted_aes_key.size(), 0);

    // Read and encrypt file
    auto file_data = readFile(filename);
    auto encrypted_file = encryptWithAES(file_data);

    // Send encrypted file
    send(sock, encrypted_file.data(), encrypted_file.size(), 0);

    EVP_PKEY_free(server_public_key);
    std::cout << "File sent successfully" << std::endl;
  }
};

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <server_ip> <filename>" << std::endl;
    return 1;
  }

  try {
    SecureFileClient client(argv[1]);
    client.sendFile(argv[2]);
  } catch (const std::exception &e) {
    std::cerr << "Client error: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
