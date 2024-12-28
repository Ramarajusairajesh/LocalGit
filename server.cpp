#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080

class RSASocket {
public:
  RSASocket() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
  }

  ~RSASocket() { ERR_free_strings(); }

  RSA *generateRSAKeyPair() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();

    if (!BN_set_word(bn, RSA_F4)) {
      handleOpenSSLErrors();
    }

    if (!RSA_generate_key_ex(rsa, 2048, bn, nullptr)) {
      handleOpenSSLErrors();
    }

    BN_free(bn);
    return rsa;
  }

  std::string rsaEncrypt(RSA *rsa, const std::string &plaintext) {
    std::string ciphertext(RSA_size(rsa), '\0');

    int len = RSA_public_encrypt(
        plaintext.size(),
        reinterpret_cast<const unsigned char *>(plaintext.c_str()),
        reinterpret_cast<unsigned char *>(&ciphertext[0]), rsa,
        RSA_PKCS1_OAEP_PADDING);

    if (len == -1) {
      handleOpenSSLErrors();
    }

    ciphertext.resize(len);
    return ciphertext;
  }

  std::string rsaDecrypt(RSA *rsa, const std::string &ciphertext) {
    std::string plaintext(RSA_size(rsa), '\0');

    int len = RSA_private_decrypt(
        ciphertext.size(),
        reinterpret_cast<const unsigned char *>(ciphertext.c_str()),
        reinterpret_cast<unsigned char *>(&plaintext[0]), rsa,
        RSA_PKCS1_OAEP_PADDING);

    if (len == -1) {
      handleOpenSSLErrors();
    }

    plaintext.resize(len);
    return plaintext;
  }

  void server() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
      perror("Socket failed");
      exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
      perror("Bind failed");
      exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
      perror("Listen failed");
      exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    if ((client_fd = accept(server_fd, (struct sockaddr *)&address,
                            (socklen_t *)&addrlen)) < 0) {
      perror("Accept failed");
      exit(EXIT_FAILURE);
    }

    RSA *rsa = generateRSAKeyPair();

    // Send public key to the client
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);
    char *pubkey;
    long pubkey_len = BIO_get_mem_data(bio, &pubkey);
    send(client_fd, pubkey, pubkey_len, 0);
    BIO_free(bio);

    // Receive encrypted message from client
    char buffer[1024] = {0};
    int valread = read(client_fd, buffer, 1024);

    std::string ciphertext(buffer, valread);
    std::string plaintext = rsaDecrypt(rsa, ciphertext);

    std::cout << "Decrypted message: " << plaintext << std::endl;

    close(client_fd);
    close(server_fd);
    RSA_free(rsa);
  }

  void client(const std::string &message) {
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("Socket creation error");
      exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
      perror("Invalid address/ Address not supported");
      exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      perror("Connection Failed");
      exit(EXIT_FAILURE);
    }

    // Receive public key from server
    char buffer[1024] = {0};
    int valread = read(sock, buffer, 1024);

    BIO *bio = BIO_new_mem_buf(buffer, valread);
    RSA *rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa) {
      handleOpenSSLErrors();
    }

    // Encrypt the message and send it
    std::string ciphertext = rsaEncrypt(rsa, message);
    send(sock, ciphertext.c_str(), ciphertext.size(), 0);

    close(sock);
    RSA_free(rsa);
  }

private:
  void handleOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
    abort();
  }
};

int main(int argc, char const *argv[]) {
  RSASocket rsaSocket;

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <server|client> [message]"
              << std::endl;
    return 1;
  }

  std::string mode = argv[1];

  if (mode == "server") {
    rsaSocket.server();
  } else if (mode == "client") {
    if (argc < 3) {
      std::cerr << "Please provide a message to send." << std::endl;
      return 1;
    }
    rsaSocket.client(argv[2]);
  } else {
    std::cerr << "Invalid mode. Use 'server' or 'client'." << std::endl;
    return 1;
  }

  return 0;
}
