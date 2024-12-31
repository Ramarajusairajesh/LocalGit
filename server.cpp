#include <archive.h>include
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
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
class SecureFileServer {
private:
  int server_fd;
  struct sockaddr_in address;
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> this->server_key;

  bool initializeRSA() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate RSA key pair
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);

    if (!ctx) {
      print_openssl_error();
      return false;
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
      print_openssl_error();
      return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0) {
      print_openssl_error();
      return false;
    }

    EVP_PKEY *key = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &key) <= 0) {
      print_openssl_error();
      return false;
    }

    this->server_key =
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(key, EVP_PKEY_free);
    return true;
  }

  bool initializeSocket() {
    int opt = 1;

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
      std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
      return false;
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
      std::cerr << "Setsockopt failed: " << strerror(errno) << std::endl;
      return false;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
      std::cerr << "Bind failed: " << strerror(errno) << std::endl;
      return false;
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
      std::cerr << "Listen failed: " << strerror(errno) << std::endl;
      return false;
    }

    return true;
  }

  std::vector<unsigned char> receiveData(int socket) {
    std::vector<unsigned char> data;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytesRead;

    // First receive the size of the data
    uint32_t dataSize;
    bytesRead = recv(socket, &dataSize, sizeof(dataSize), 0);
    if (bytesRead != sizeof(dataSize)) {
      throw std::runtime_error("Failed to receive data size");
    }
    dataSize = ntohl(dataSize);

    // Then receive the actual data
    while (data.size() < dataSize) {
      bytesRead = recv(
          socket, buffer,
          std::min(static_cast<size_t>(BUFFER_SIZE), dataSize - data.size()),
          0);
      if (bytesRead <= 0) {
        if (bytesRead == 0) {
          throw std::runtime_error("Connection closed by peer");
        }
        throw std::runtime_error(std::string("Receive error: ") +
                                 strerror(errno));
      }
      data.insert(data.end(), buffer, buffer + bytesRead);
    }

    return data;
  }

  void sendData(int socket, const std::vector<unsigned char> &data) {
    // First send the size of the data
    uint32_t dataSize = htonl(data.size());
    if (send(socket, &dataSize, sizeof(dataSize), 0) != sizeof(dataSize)) {
      throw std::runtime_error("Failed to send data size");
    }

    // Then send the actual data
    size_t totalSent = 0;
    while (totalSent < data.size()) {
      ssize_t sent =
          send(socket, data.data() + totalSent, data.size() - totalSent, 0);
      if (sent <= 0) {
        throw std::runtime_error(std::string("Send error: ") + strerror(errno));
      }
      totalSent += sent;
    }
  }

  void handleFileTransfer(int client_socket) {
    try {
      // Send server's public key
      BIO *bio = BIO_new(BIO_s_mem());
      if (!bio) {
        throw std::runtime_error("Failed to create BIO");
      }

      if (!PEM_write_bio_PUBKEY(bio, this->server_key.get())) {
        BIO_free(bio);
        throw std::runtime_error("Failed to write public key");
      }

      char *pub_key_data;
      long pub_key_size = BIO_get_mem_data(bio, &pub_key_data);
      std::vector<unsigned char> pub_key_vec(pub_key_data,
                                             pub_key_data + pub_key_size);
      sendData(client_socket, pub_key_vec);
      BIO_free(bio);

      // Receive encrypted AES key
      auto encrypted_aes_key = receiveData(client_socket);

      // Decrypt AES key using server's private key
      std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
          EVP_PKEY_CTX_new(this->server_key.get(), nullptr), EVP_PKEY_CTX_free);

      if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize decryption context");
      }

      size_t decrypted_len;
      if (EVP_PKEY_decrypt(ctx.get(), nullptr, &decrypted_len,
                           encrypted_aes_key.data(),
                           encrypted_aes_key.size()) <= 0) {
        throw std::runtime_error("Failed to determine decrypted length");
      }

      std::vector<unsigned char> aes_key(decrypted_len);
      if (EVP_PKEY_decrypt(ctx.get(), aes_key.data(), &decrypted_len,
                           encrypted_aes_key.data(),
                           encrypted_aes_key.size()) <= 0) {
        throw std::runtime_error("Failed to decrypt AES key");
      }

      // Receive encrypted file data
      auto encrypted_file = receiveData(client_socket);

      // Decrypt file using AES key
      std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> aes_ctx(
          EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

      if (!aes_ctx) {
        throw std::runtime_error("Failed to create AES context");
      }

      // IV is first 16 bytes of encrypted file
      if (encrypted_file.size() < 16) {
        throw std::runtime_error("Encrypted file too short");
      }

      if (EVP_DecryptInit_ex(aes_ctx.get(), EVP_aes_256_cbc(), nullptr,
                             aes_key.data(), encrypted_file.data()) <= 0) {
        throw std::runtime_error("Failed to initialize AES decryption");
      }

      std::vector<unsigned char> decrypted_file;
      std::vector<unsigned char> buffer(encrypted_file.size());
      int update_len, final_len;

      if (EVP_DecryptUpdate(aes_ctx.get(), buffer.data(), &update_len,
                            encrypted_file.data() + 16,
                            encrypted_file.size() - 16) <= 0) {
        throw std::runtime_error("Failed to decrypt file data");
      }
      decrypted_file.insert(decrypted_file.end(), buffer.begin(),
                            buffer.begin() + update_len);

      if (EVP_DecryptFinal_ex(aes_ctx.get(), buffer.data(), &final_len) <= 0) {
        throw std::runtime_error("Failed to finalize decryption");
      }
      decrypted_file.insert(decrypted_file.end(), buffer.begin(),
                            buffer.begin() + final_len);

      // Save decrypted file
      std::string filename = "received_file.dat";
      std::ofstream output_file(filename, std::ios::binary);
      if (!output_file) {
        throw std::runtime_error("Failed to create output file");
      }
      output_file.write((char *)decrypted_file.data(), decrypted_file.size());
      output_file.close();

      std::cout << "File received and saved as: " << filename << std::endl;
    } catch (const std::exception &e) {
      std::cerr << "Error in handleFileTransfer: " << e.what() << std::endl;
      print_openssl_error();
      throw;
    }
  }

public:
  SecureFileServer() : server_fd(-1), this->server_key(nullptr, EVP_PKEY_free) {
    if (!initializeRSA()) {
      throw std::runtime_error("Failed to initialize RSA");
    }
    if (!initializeSocket()) {
      throw std::runtime_error("Failed to initialize socket");
    }
  }

  ~SecureFileServer() {
    if (server_fd >= 0) {
      close(server_fd);
    }
  }

  void start() {
    std::cout << "Server listening on port " << PORT << std::endl;

    while (true) {
      int client_socket;
      struct sockaddr_in client_addr;
      socklen_t addrlen = sizeof(client_addr);

      client_socket =
          accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
      if (client_socket < 0) {
        std::cerr << "Accept failed: " << strerror(errno) << std::endl;
        continue;
      }

      std::cout << "Client connected from " << inet_ntoa(client_addr.sin_addr)
                << std::endl;

      try {
        handleFileTransfer(client_socket);
      } catch (const std::exception &e) {
        std::cerr << "Error handling file transfer: " << e.what() << std::endl;
      }

      close(client_socket);
    }
  }
};

void sendData(int socket, const std::vector<unsigned char> &data) {
  // First send the size of the data
  uint32_t dataSize = htonl(data.size());
  if (send(socket, &dataSize, sizeof(dataSize), 0) != sizeof(dataSize)) {
    throw std::runtime_error("Failed to send data size");
  }

  // Then send the actual data
  size_t totalSent = 0;
  while (totalSent < data.size()) {
    ssize_t sent =
        send(socket, data.data() + totalSent, data.size() - totalSent, 0);
    if (sent <= 0) {
      throw std::runtime_error(std::string("Send error: ") + strerror(errno));
    }
    totalSent += sent;
  }
}

void handleFileTransfer(int client_socket) {
  try {
    // Send server's public key
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
      throw std::runtime_error("Failed to create BIO");
    }

    if (!PEM_write_bio_PUBKEY(bio, this->server_key.get())) {
      BIO_free(bio);
      throw std::runtime_error("Failed to write public key");
    }

    char *pub_key_data;
    long pub_key_size = BIO_get_mem_data(bio, &pub_key_data);
    std::vector<unsigned char> pub_key_vec(pub_key_data,
                                           pub_key_data + pub_key_size);
    sendData(client_socket, pub_key_vec);
    BIO_free(bio);

    // Receive encrypted AES key
    auto encrypted_aes_key = receiveData(client_socket);

    // Decrypt AES key using server's private key
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(this->server_key.get(), nullptr), EVP_PKEY_CTX_free);

    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
      throw std::runtime_error("Failed to initialize decryption context");
    }

    size_t decrypted_len;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &decrypted_len,
                         encrypted_aes_key.data(),
                         encrypted_aes_key.size()) <= 0) {
      throw std::runtime_error("Failed to determine decrypted length");
    }

    std::vector<unsigned char> aes_key(decrypted_len);
    if (EVP_PKEY_decrypt(ctx.get(), aes_key.data(), &decrypted_len,
                         encrypted_aes_key.data(),
                         encrypted_aes_key.size()) <= 0) {
      throw std::runtime_error("Failed to decrypt AES key");
    }

    // Receive encrypted file data
    auto encrypted_file = receiveData(client_socket);

    // Decrypt file using AES key
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> aes_ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!aes_ctx) {
      throw std::runtime_error("Failed to create AES context");
    }

    // IV is first 16 bytes of encrypted file
    if (encrypted_file.size() < 16) {
      throw std::runtime_error("Encrypted file too short");
    }

    if (EVP_DecryptInit_ex(aes_ctx.get(), EVP_aes_256_cbc(), nullptr,
                           aes_key.data(), encrypted_file.data()) <= 0) {
      throw std::runtime_error("Failed to initialize AES decryption");
    }

    std::vector<unsigned char> decrypted_file;
    std::vector<unsigned char> buffer(encrypted_file.size());
    int update_len, final_len;

    if (EVP_DecryptUpdate(aes_ctx.get(), buffer.data(), &update_len,
                          encrypted_file.data() + 16,
                          encrypted_file.size() - 16) <= 0) {
      throw std::runtime_error("Failed to decrypt file data");
    }
    decrypted_file.insert(decrypted_file.end(), buffer.begin(),
                          buffer.begin() + update_len);

    if (EVP_DecryptFinal_ex(aes_ctx.get(), buffer.data(), &final_len) <= 0) {
      throw std::runtime_error("Failed to finalize decryption");
    }
    decrypted_file.insert(decrypted_file.end(), buffer.begin(),
                          buffer.begin() + final_len);

    // Save decrypted file
    std::string filename = "received_file.dat";
    std::ofstream output_file(filename, std::ios::binary);
    if (!output_file) {
      throw std::runtime_error("Failed to create output file");
    }
    output_file.write((char *)decrypted_file.data(), decrypted_file.size());
    output_file.close();

    std::cout << "File received and saved as: " << filename << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "Error in handleFileTransfer: " << e.what() << std::endl;
    print_openssl_error();
    throw;
  }
}

public:
SecureFileServer() : server_fd(-1), this->server_key(nullptr, EVP_PKEY_free) {
  if (!initializeRSA()) {
    throw std::runtime_error("Failed to initialize RSA");
  }
  if (!initializeSocket()) {
    throw std::runtime_error("Failed to initialize socket");
  }
}

~SecureFileServer() {
  if (server_fd >= 0) {
    close(server_fd);
  }
}

void start() {
  std::cout << "Server listening on port " << PORT << std::endl;

  while (true) {
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    client_socket =
        accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
    if (client_socket < 0) {
      std::cerr << "Accept failed: " << strerror(errno) << std::endl;
      continue;
    }

    std::cout << "Client connected from " << inet_ntoa(client_addr.sin_addr)
              << std::endl;

    try {
      handleFileTransfer(client_socket);
    } catch (const std::exception &e) {
      std::cerr << "Error handling file transfer: " << e.what() << std::endl;
    }

    close(client_socket);
  }
};

int main() {
  try {
    SecureFileServer server;
    server.start();
  } catch (const std::exception &e) {
    std::cerr << "Server error: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
