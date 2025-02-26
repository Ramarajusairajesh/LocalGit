#include <asio.hpp>
#include <cstdlib>
#include <iostream>

int main(int argc, char *argv[]) {
  int choice;
  std::cout << "(1)Chat server ? (2)File sharing for version controlling ?"
            << std::endl;
  std::cin >> choice;
  if (choice == 1) {
    int chat_server = system("./chat_server.out");
  } else if (choice == 2) {
    int git_server = system("./file_sharing.out");
  } else {

    std::cout << "Please select a proper option";
  }

  return EXIT_SUCCESS;
}
