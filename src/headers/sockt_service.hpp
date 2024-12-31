#include <arpa/inet.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define BUFFER 65535
#define port 8080
using namespace std;
int transfer_data(const char *compress_file, int fd) {
  ifstream file(compress_file, ios::binary);
  char buffer[BUFFER] = {0};

  if (!file.is_open()) {
    cerr << "File(s) opening failed either the file(s) don't exit or you don't "
            "have permission to read / edit"
         << endl;
    close(fd);
    return EXIT_FAILURE;
  }
  while (file.good()) {
    file.read(buffer, BUFFER);
    size_t bytes_read = file.gcount();
    send(fd, buffer, bytes_read, 0);
  }
  file.close();
  close(fd);

  return EXIT_SUCCESS;
}

int recv_data(int fd) {
  char buffer[BUFFER] = {0};
  recv(fd, buffer, BUFFER, 0);
  // Write the binary data into a file

  return EXIT_SUCCESS;
}
int create_socket() {
  int server_fd, new_socket;
  int opt = 1;
  struct sockaddr_in address;
  socklen_t addrlength = sizeof(address);
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    cerr << "Error while creating socket" << endl;
    return EXIT_FAILURE;
  }
  // Attach the socket to the port forcefully and make it reusable
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
    cerr << "Setting options for socket leads to an error";
    return EXIT_FAILURE;
  }
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = INADDR_ANY;
  return EXIT_SUCCESS;
}
