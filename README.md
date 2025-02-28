# LocalGit
{! Work in progress } !
LocalGit is a decentralized, lightweight, and secure file-sharing system built in C++. As an alternative to GitHub, I created this project to run in a LAN. Instead of using Git as its building block, I wrote my own file-sharing service.

## Features
- **RSA Key Sharing with OpenSSL**: Uses `libssl` for secure key exchanges for AES.
- **AES Encryption**: Encrypts shared files with AES for confidentiality.
- **Asynchronous File Sharing**: Built on `Boost.Asio` for efficient and non-blocking file transfers.
- **Async Chatting**: Enables real-time communication between multiple users.
- **Archiving and Compression**: Uses `libarchive` and `zlib` for archiving folders and compressing data into a single file to reduce bandwidth usage and enable easy transfer.

## Dependencies
- C++14 or later
- OpenSSL (`libssl`)
- Boost.Asio
- CMake (for building)

## Build and Run
```sh
git clone https://github.com/Ramarajusairajesh/LocalGit.git
cd LocalGit
mkdir build && cd build
cmake ..
make
./localgit
```

## How It Works
After running the server, it generates two RSA keys: one public and one private. The public key is shared along with the binary to clients/users. Clients generate their own AES-256 encryption key to transfer data securely. This key is shared with the server using RSA encryption, and the server decrypts it for use with the client.

I used `boost::asio` to create an asynchronous file transfer system with four threads handling file server requests. AES-256 encryption is used for secure file sharing between the server and clients. Later, for chat functionality, I implemented the same encryption method and ran the chat server on a single thread. All access requests and chat logs are recorded in a local log file, similar to any other network-attached software.

## Usage
- Start the LocalGit server.
- Connect clients for secure file sharing and chat.

