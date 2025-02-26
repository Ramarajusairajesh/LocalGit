
#include <boost/asio.hpp>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <memory>
#include <thread>

using boost::asio::ip::tcp;

//----------------------------------------------------------------------
// ChatSession: Handles a single client connection for the server.
class ChatSession : public std::enable_shared_from_this<ChatSession> {
public:
  explicit ChatSession(tcp::socket socket) : socket_(std::move(socket)) {}

  void start() { do_read(); }

  // Simple delivery that queues a message and writes it back.
  void deliver(const std::string &msg) {
    bool write_in_progress = !write_msgs_.empty();
    write_msgs_.push_back(msg);
    if (!write_in_progress) {
      do_write();
    }
  }

private:
  void do_read() {
    auto self(shared_from_this());
    socket_.async_read_some(
        boost::asio::buffer(data_, max_length),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (!ec) {
            std::string msg(data_, length);
            std::cout << "Server received: " << msg << std::endl;
            deliver(msg);
            do_read();
          }
        });
  }

  void do_write() {
    auto self(shared_from_this());
    boost::asio::async_write(
        socket_,
        boost::asio::buffer(write_msgs_.front().data(),
                            write_msgs_.front().length()),
        [this, self](boost::system::error_code ec, std::size_t /*length*/) {
          if (!ec) {
            write_msgs_.pop_front();
            if (!write_msgs_.empty()) {
              do_write();
            }
          }
        });
  }

  tcp::socket socket_;
  enum { max_length = 1024 };
  char data_[max_length];
  std::deque<std::string> write_msgs_;
};

//----------------------------------------------------------------------
// ChatServer: Accepts connections and starts ChatSession for each client.
class ChatServer {
public:
  ChatServer(boost::asio::io_context &io_context, const tcp::endpoint &endpoint)
      : acceptor_(io_context, endpoint) {
    do_accept();
  }

private:
  void do_accept() {
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket) {
          if (!ec) {
            std::make_shared<ChatSession>(std::move(socket))->start();
          }
          do_accept();
        });
  }

  tcp::acceptor acceptor_;
};

//----------------------------------------------------------------------
// ChatClient: Connects to the chat server and handles user I/O.
class ChatClient {
public:
  ChatClient(boost::asio::io_context &io_context,
             const tcp::resolver::results_type &endpoints)
      : io_context_(io_context), socket_(io_context) {
    do_connect(endpoints);
  }

  void write(const std::string &msg) {
    boost::asio::post(io_context_, [this, msg]() {
      bool write_in_progress = !write_msgs_.empty();
      write_msgs_.push_back(msg);
      if (!write_in_progress) {
        do_write();
      }
    });
  }

  void close() {
    boost::asio::post(io_context_, [this]() { socket_.close(); });
  }

private:
  void do_connect(const tcp::resolver::results_type &endpoints) {
    boost::asio::async_connect(
        socket_, endpoints,
        [this](boost::system::error_code ec, tcp::endpoint) {
          if (!ec) {
            do_read();
          }
        });
  }

  void do_read() {
    boost::asio::async_read_until(
        socket_, boost::asio::dynamic_buffer(read_msg_), '\n',
        [this](boost::system::error_code ec, std::size_t length) {
          if (!ec) {
            std::cout << "Message from server: " << read_msg_.substr(0, length);
            read_msg_.erase(0, length);
            do_read();
          }
        });
  }

  void do_write() {
    auto msg = write_msgs_.front() + "\n";
    boost::asio::async_write(
        socket_, boost::asio::buffer(msg.data(), msg.length()),
        [this](boost::system::error_code ec, std::size_t /*length*/) {
          if (!ec) {
            write_msgs_.pop_front();
            if (!write_msgs_.empty()) {
              do_write();
            }
          }
        });
  }

  boost::asio::io_context &io_context_;
  tcp::socket socket_;
  std::string read_msg_;
  std::deque<std::string> write_msgs_;
};

// Running the chat server on a single thread since text based chatting doesn't
// require much computation power! Will change it to multi thread if the server
// feels slow OR messages takes long time to pass!
int main(int argc, char *argv[]) {
  try {
    if (argc < 2) {
      std::cerr << "Usage:\n  To run as server: " << argv[0]
                << " server <port>\n"
                << "  To run as client: " << argv[0]
                << " client <host> <port>\n";
      return 1;
    }

    std::string mode = argv[1];
    boost::asio::io_context io_context;

    if (mode == "server") {
      if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " server <port>\n";
        return 1;
      }
      tcp::endpoint endpoint(tcp::v4(), std::atoi(argv[2]));
      ChatServer server(io_context, endpoint);
      // Run all asynchronous operations on the single main thread.
      io_context.run();
    } else if (mode == "client") {
      std::string username;
      std::cout << "Welcome , Enter your name";
      std::cin >> username;
      if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " client <host> <port>\n";
        return 1;
      }
      tcp::resolver resolver(io_context);
      auto endpoints = resolver.resolve(argv[2], argv[3]);
      ChatClient client(io_context, endpoints);

      std::thread t([&io_context]() { io_context.run(); });

      std::string line;
      while (std::getline(std::cin, line))
        client.write(line);

      client.close();
      t.join();
    } else {
      std::cerr << "Invalid mode. Use 'server' or 'client'.\n";
    }
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
