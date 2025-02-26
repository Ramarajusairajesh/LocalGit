# LocalGit

LocalGit is a decentralized, lightweight, and secure file-sharing system built in C++. As an alternative to github I created this project but to run in a LAN , instead of using git
as it's building blog I written my own file sharing service

## Features
- **RSA Key Sharing with OpenSSL**: Uses `libssl` for secure key exchanges for AES!
- **AES Encryption**: Encrypts shared files with AES for confidentiality.
- **Asynchronous File Sharing**: Built on `Boost.Asio` for efficient and non-blocking file transfers.
- **Async Chatting**: Enables real-time communication between multiple users.
- **Archiving and compression**: Uses libar and gzlib for archiving the folder and compressing the data to a single file to reduce bandwidth and easy transfer 

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

##How it works
After running the server part it generate two RSA keys, one public and one private ! The public was shared along with the binary and client /users ! clients generate there own key for
AES 256 encryption to transfer data securely ! This key is shared to server using RSA, at server the key was decrypted for use to use with client!

I used boost::asio for creating async file transfering , created 4 threads for the file server to keep up with the request , later for the chat functionality I used the same encryption
method and ran the chatting server on a single thread !All the access requests and chat are recorded in a local log file same as any other network attached software !


## Usage
- Start the LocalGit server.
- Connect clients for secure file sharing and chat.



## Contributing
Feel free to fork, open issues, and submit pull requests!

## License
MIT License
