#ifndef ARCHIVING_H
#define ARCHIVING_H

#include <archive.h>
#include <archive_entry.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define HASH_LEN 65

/**
 * @brief Prints OpenSSL error messages to stderr
 */
inline void print_openssl_error() {
  char err_buf[256];
  ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
  std::cerr << "OpenSSL Error: " << err_buf << std::endl;
}

/**
 * @brief Extracts all files from a tar archive
 * @param filename Path to the tar file
 * @return 0 on success, error code on failure
 */
inline int tar_extract_all(const char *filename) {
  struct archive *a;
  struct archive *ext;
  struct archive_entry *entry;
  int flags;
  int r;

  a = archive_read_new();
  ext = archive_write_disk_new();
  archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME);
  flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL |
          ARCHIVE_EXTRACT_FFLAGS;
  archive_read_support_format_tar(a);

  if ((r = archive_read_open_filename(a, filename, 10240))) {
    fprintf(stderr, "Could not open %s: %s\n", filename,
            archive_error_string(a));
    return r;
  }

  while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
    printf("Extracting: %s\n", archive_entry_pathname(entry));
    archive_write_header(ext, entry);

    const void *buff;
    size_t size;
    la_int64_t offset;

    while ((r = archive_read_data_block(a, &buff, &size, &offset)) ==
           ARCHIVE_OK) {
      archive_write_data_block(ext, buff, size, offset);
    }
    archive_write_finish_entry(ext);
  }

  archive_read_close(a);
  archive_read_free(a);
  archive_write_close(ext);
  archive_write_free(ext);

  return 0;
}

/**
 * @brief Calculates SHA-256 hash of a file
 * @param filename Path to the file
 * @param hash_out Buffer to store the resulting hash string (must be at least
 * HASH_LEN bytes)
 */
inline void calculate_hash(const char *filename, char *hash_out) {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Failed to create EVP context\n");
    exit(EXIT_FAILURE);
  }

  FILE *file = fopen(filename, "rb");
  if (!file) {
    perror("Failed to open file for hashing");
    EVP_MD_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    fprintf(stderr, "Failed to initialize digest\n");
    fclose(file);
    EVP_MD_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  unsigned char buffer[8192];
  size_t bytes_read;
  while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
    if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
      fprintf(stderr, "Failed to update digest\n");
      fclose(file);
      EVP_MD_CTX_free(ctx);
      exit(EXIT_FAILURE);
    }
  }

  fclose(file);

  if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    fprintf(stderr, "Failed to finalize digest\n");
    EVP_MD_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  EVP_MD_CTX_free(ctx);

  for (unsigned int i = 0; i < hash_len; i++) {
    sprintf(hash_out + (i * 2), "%02x", hash[i]);
  }
  hash_out[HASH_LEN - 1] = '\0';
}

/**
 * @brief Creates a tar archive from a list of files
 * @param tar_name Name of the tar file to create
 * @param num_files Number of files to include
 * @param file_list Array of file paths to include
 * @return 0 on success, -1 on failure
 */
inline int create_tar(const char *tar_name, int num_files, char *file_list[]) {
  struct archive *a;
  struct archive_entry *entry;
  FILE *file;
  size_t bytes_read;
  char buffer[8192];

  a = archive_write_new();
  archive_write_set_format_pax_restricted(a);

  if (archive_write_open_filename(a, tar_name) != ARCHIVE_OK) {
    fprintf(stderr, "Could not create tar archive: %s\n",
            archive_error_string(a));
    archive_write_free(a);
    return -1;
  }

  for (int i = 0; i < num_files; i++) {
    const char *file_name = file_list[i];
    file = fopen(file_name, "rb");
    if (!file) {
      perror("Failed to open input file");
      archive_write_free(a);
      return -1;
    }

    entry = archive_entry_new();
    archive_entry_set_pathname(entry, file_name);
    fseek(file, 0, SEEK_END);
    archive_entry_set_size(entry, ftell(file));
    fseek(file, 0, SEEK_SET);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_write_header(a, entry);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
      archive_write_data(a, buffer, bytes_read);
    }

    fclose(file);
    archive_entry_free(entry);
  }

  archive_write_close(a);
  archive_write_free(a);

  return 0;
}

#endif // ARCHIVING_H
