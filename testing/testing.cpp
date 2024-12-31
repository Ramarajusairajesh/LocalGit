#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_LEN 65 // 64 for SHA256 + 1 for null terminator

// Function to calculate the SHA-256 hash of the tar archive using EVP API
void calculate_hash(const char *filename, char *hash_out) {
  unsigned char hash[EVP_MAX_MD_SIZE]; // Buffer for the hash
  unsigned int hash_len;               // Length of the resulting hash
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();  // Allocate a digest context
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

  // Initialize the digest operation
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    fprintf(stderr, "Failed to initialize digest\n");
    fclose(file);
    EVP_MD_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Read the file and update the hash
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

  // Finalize the digest operation
  if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    fprintf(stderr, "Failed to finalize digest\n");
    EVP_MD_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  EVP_MD_CTX_free(ctx);

  // Convert the hash to a hexadecimal string
  for (unsigned int i = 0; i < hash_len; i++) {
    sprintf(hash_out + (i * 2), "%02x", hash[i]);
  }
  hash_out[HASH_LEN - 1] = '\0'; // Null-terminate the hash string
}

// Function to create a tar archive from a list of files
int create_tar(const char *tar_name, int num_files, char *file_list[]) {
  struct archive *a;
  struct archive_entry *entry;
  FILE *file;
  size_t bytes_read;
  char buffer[8192];

  // Initialize the tar archive
  a = archive_write_new();
  archive_write_set_format_pax_restricted(a); // Portable tar format

  if (archive_write_open_filename(a, tar_name) != ARCHIVE_OK) {
    fprintf(stderr, "Could not create tar archive: %s\n",
            archive_error_string(a));
    archive_write_free(a);
    return -1;
  }

  // Add each file to the tar archive
  for (int i = 0; i < num_files; i++) {
    const char *file_name = file_list[i];
    file = fopen(file_name, "rb");
    if (!file) {
      perror("Failed to open input file");
      archive_write_free(a);
      return -1;
    }

    // Create a new archive entry
    entry = archive_entry_new();
    archive_entry_set_pathname(entry, file_name);
    fseek(file, 0, SEEK_END);
    archive_entry_set_size(entry, ftell(file)); // Set file size
    fseek(file, 0, SEEK_SET);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644); // Set file permissions
    archive_write_header(a, entry);

    // Write file contents to the tar archive
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
      archive_write_data(a, buffer, bytes_read);
    }

    fclose(file);
    archive_entry_free(entry);
  }

  // Finalize the archive
  archive_write_close(a);
  archive_write_free(a);

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <file1> <file2> ...\n", argv[0]);
    return EXIT_FAILURE;
  }

  const char *temp_tar_name =
      "temp_archive.tar"; // Temporary name for the tar file
  char hash[HASH_LEN];

  // Create the tar archive
  if (create_tar(temp_tar_name, argc - 1, &argv[1]) != 0) {
    fprintf(stderr, "Failed to create tar archive\n");
    return EXIT_FAILURE;
  }

  // Calculate the hash of the tar archive
  calculate_hash(temp_tar_name, hash);

  // Rename the tar archive to its hash
  char final_tar_name[HASH_LEN + 4]; // Add space for ".tar"
  snprintf(final_tar_name, sizeof(final_tar_name), "%s.tar", hash);

  if (rename(temp_tar_name, final_tar_name) != 0) {
    perror("Failed to rename tar archive");
    return EXIT_FAILURE;
  }

  printf("Created tar archive: %s\n", final_tar_name);

  return EXIT_SUCCESS;
}
