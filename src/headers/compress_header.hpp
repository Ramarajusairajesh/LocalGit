#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <zlib.h>

using namespace std;

// Function to compress a file using zlib
bool compressFile(const string &inputFile, const string &outputFile) {
  ifstream in(inputFile, ios::binary);
  if (!in) {
    cerr << "Error opening input file: " << inputFile << endl;
    return false;
  }

  ofstream out(outputFile, ios::binary);
  if (!out) {
    cerr << "Error opening output file: " << outputFile << endl;
    in.close();
    return false;
  }

  z_stream def = {0};
  def.zalloc = Z_NULL;
  def.zfree = Z_NULL;
  def.opaque = Z_NULL;

  if (deflateInit(&def, Z_DEFAULT_COMPRESSION) != Z_OK) {
    cerr << "Error initializing zlib for compression" << endl;
    in.close();
    out.close();
    return false;
  }

  const size_t chunkSize = 1024;
  vector<char> inBuffer(chunkSize);
  vector<char> outBuffer(chunkSize);
  int ret;

  do {
    in.read(inBuffer.data(), chunkSize);
    def.avail_in = in.gcount();
    def.next_in = reinterpret_cast<Bytef *>(inBuffer.data());

    do {
      def.avail_out = chunkSize;
      def.next_out = reinterpret_cast<Bytef *>(outBuffer.data());

      ret = deflate(&def, in.eof() ? Z_FINISH : Z_NO_FLUSH);
      if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_FINISH) {
        cerr << "Error during zlib compression" << endl;
        deflateEnd(&def);
        in.close();
        out.close();
        return false;
      }

      out.write(outBuffer.data(), chunkSize - def.avail_out);
    } while (def.avail_out == 0);

  } while (!in.eof());

  deflateEnd(&def);
  in.close();
  out.close();
  return true;
}

// Function to decompress a file using zlib
bool decompressFile(const string &inputFile, const string &outputFile) {
  ifstream in(inputFile, ios::binary);
  if (!in) {
    cerr << "Error opening input file: " << inputFile << endl;
    return false;
  }

  ofstream out(outputFile, ios::binary);
  if (!out) {
    cerr << "Error opening output file: " << outputFile << endl;
    in.close();
    return false;
  }

  z_stream inf = {0};
  inf.zalloc = Z_NULL;
  inf.zfree = Z_NULL;
  inf.opaque = Z_NULL;

  if (inflateInit(&inf) != Z_OK) {
    cerr << "Error initializing zlib for decompression" << endl;
    in.close();
    out.close();
    return false;
  }

  const size_t chunkSize = 1024;
  vector<char> inBuffer(chunkSize);
  vector<char> outBuffer(chunkSize);
  int ret;

  do {
    in.read(inBuffer.data(), chunkSize);
    inf.avail_in = in.gcount();
    inf.next_in = reinterpret_cast<Bytef *>(inBuffer.data());

    do {
      inf.avail_out = chunkSize;
      inf.next_out = reinterpret_cast<Bytef *>(outBuffer.data());

      ret = inflate(&inf, Z_NO_FLUSH);
      if (ret != Z_OK && ret != Z_STREAM_END) {
        cerr << "Error during zlib decompression" << endl;
        inflateEnd(&inf);
        in.close();
        out.close();
        return false;
      }

      out.write(outBuffer.data(), chunkSize - inf.avail_out);
    } while (inf.avail_out == 0);

  } while (ret != Z_STREAM_END);

  inflateEnd(&inf);
  in.close();
  out.close();
  return true;
}
