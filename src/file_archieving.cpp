extern "C" {
#include <archive.h>
#include <archive_entry.h>
};
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs = std::filesystem;
using std::cerr, std::cout, std::endl, std::string;

class TarArchive {
public:
  bool create(const string &archiveName, const string &sourceDirectory) {

    if (!fs::exists(sourceDirectory)) {
      cerr << "Error: Source directory does not exist: " << sourceDirectory
           << endl;
      return false;
    }

    struct archive *a = archive_write_new();
    archive_write_add_filter_bzip2(a);
    archive_write_set_format_pax_restricted(a);
    if (archive_write_open_filename(a, archiveName.c_str()) != ARCHIVE_OK) {
      cerr << "Error: " << archive_error_string(a) << endl;
      return false;
    }

    std::error_code ec;
    for (const auto &entry : fs::recursive_directory_iterator(
             sourceDirectory, fs::directory_options::skip_permission_denied,
             ec)) {
      if (ec) {
        cerr << "Warning: " << ec.message() << " at " << entry.path().string()
             << endl;
        ec.clear();
        continue;
      }

      if (!addFileToArchive(a, entry.path(), sourceDirectory)) {
        archive_write_close(a);
        archive_write_free(a);
        return false;
      }
    }

    archive_write_close(a);
    archive_write_free(a);
    return true;
  }

  bool extract(const string &archiveName, const string &outputDirectory) {

    std::error_code ec;
    if (!fs::exists(outputDirectory)) {
      fs::create_directories(outputDirectory, ec);
      if (ec) {
        cerr << "Error: Failed to create output directory: " << ec.message()
             << endl;
        return false;
      }
    }

    struct archive *a = archive_read_new();
    archive_read_support_format_tar(a);
    archive_read_support_filter_bzip2(a);

    if (archive_read_open_filename(a, archiveName.c_str(), 10240) !=
        ARCHIVE_OK) {
      cerr << "Error: " << archive_error_string(a) << endl;
      return false;
    }

    struct archive *ext = archive_write_disk_new();
    archive_write_disk_set_options(ext,
                                   ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM);

    struct archive_entry *entry;
    int result;
    while ((result = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
      const string outPath =
          outputDirectory + "/" + archive_entry_pathname(entry);
      archive_entry_set_pathname(entry, outPath.c_str());

      if (archive_write_header(ext, entry) != ARCHIVE_OK) {
        cerr << "Failed to write header: " << archive_error_string(ext) << endl;
        continue;
      }

      copyData(a, ext);
      archive_write_finish_entry(ext);
    }

    if (result != ARCHIVE_EOF) {
      cerr << "Error reading archive: " << archive_error_string(a) << endl;
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    return (result == ARCHIVE_EOF);
  }

private:
  bool addFileToArchive(struct archive *a, const fs::path &filePath,
                        const string &baseDir) {
    struct archive_entry *entry = archive_entry_new();
    string relativePath = fs::relative(filePath, baseDir).string();

    archive_entry_set_pathname(entry, relativePath.c_str());

    std::error_code ec;
    bool is_regular = fs::is_regular_file(filePath, ec);
    if (ec) {
      cerr << "Error checking file type: " << ec.message() << " for "
           << filePath.string() << endl;
      archive_entry_free(entry);
      return false;
    }

    if (is_regular) {
      archive_entry_set_size(entry, fs::file_size(filePath, ec));
      if (ec) {
        cerr << "Error getting file size: " << ec.message() << " for "
             << filePath.string() << endl;
        archive_entry_free(entry);
        return false;
      }
      archive_entry_set_filetype(entry, AE_IFREG);
    } else if (fs::is_directory(filePath, ec)) {
      archive_entry_set_size(entry, 0);
      archive_entry_set_filetype(entry, AE_IFDIR);
    } else {

      archive_entry_free(entry);
      return true;
    }

    archive_entry_set_perm(entry, 0644);

    if (archive_write_header(a, entry) != ARCHIVE_OK) {
      cerr << "Failed to write header: " << archive_error_string(a) << endl;
      archive_entry_free(entry);
      return false;
    }

    if (is_regular) {
      std::ifstream file(filePath, std::ios::binary);
      if (!file) {
        cerr << "Failed to open file for reading: " << filePath.string()
             << endl;
        archive_entry_free(entry);
        return false;
      }

      char buffer[8192];
      while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        archive_write_data(a, buffer, file.gcount());
      }
    }

    archive_entry_free(entry);
    return true;
  }

  void copyData(struct archive *ar, struct archive *aw) {
    const void *buff;
    size_t size;
    la_int64_t offset;

    int r;
    while ((r = archive_read_data_block(ar, &buff, &size, &offset)) ==
           ARCHIVE_OK) {
      if (archive_write_data_block(aw, buff, size, offset) != ARCHIVE_OK) {
        cerr << "Error writing data block: " << archive_error_string(aw)
             << endl;
        break;
      }
    }

    if (r != ARCHIVE_EOF) {
      cerr << "Error reading data block: " << archive_error_string(ar) << endl;
    }
  }
};

void __help() {
  cout << "Usage: tar -x tarfile.tar.gz OutputDirectory" << endl;
  cout << "       tar -c directory tarfile_name.tar" << endl;
  cout << "       tar -c directory" << endl;
}

int main(int argc, char *argv[]) {

  TarArchive tar;
  string mode = argv[1];
  if (argc < 3) {
    __help();
    return EXIT_FAILURE;
  }
  if (mode == "--extract" || mode == "-e") {

    string archiveFile = argv[2];
    string OutputDir;

    if (argc < 4) {

      OutputDir = archiveFile;
      size_t lastDot = OutputDir.find_first_of('.');
      if (lastDot != string::npos) {
        OutputDir = OutputDir.substr(0, lastDot);
      }
    } else {
      OutputDir = argv[3];
    }

    if (!fs::exists(archiveFile)) {
      cerr << "Error: Archive file does not exist: " << archiveFile << endl;
      return EXIT_FAILURE;
    }

    if (tar.extract(archiveFile, OutputDir)) {
      cout << "Archive extracted successfully to: " << OutputDir << endl;
    } else {
      cerr << "Failed to extract archive." << endl;
      return EXIT_FAILURE;
    }
  } else if (mode == "--create" || mode == "-c") {
    string sourceDir = argv[2];
    string archiveFile;

    if (argc < 4) {

      archiveFile = sourceDir;
      if (archiveFile.back() == '/') {
        archiveFile.pop_back();
      }
      archiveFile += ".tar.bz2";
    } else {
      archiveFile = argv[3];
    }

    if (!fs::exists(sourceDir)) {
      cerr << "Error: Source directory does not exist: " << sourceDir << endl;
      return EXIT_FAILURE;
    }

    if (tar.create(archiveFile, sourceDir)) {
      cout << "Archive created successfully: " << archiveFile << endl;
    } else {
      cerr << "Failed to create archive." << endl;
      return EXIT_FAILURE;
    }
  } else {
    __help();
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
