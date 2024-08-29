#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#define DIGEST_NAME "sha512-256"

int main(int argc, char *argv[]) {
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  char mess1[] = "Test Message\n";
  char mess2[] = "Hello World\n";
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, i;

  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname(DIGEST_NAME);
  if(!md) {
    printf("Unknown message digest %s\n", DIGEST_NAME);
    exit(1);
  }
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
  EVP_DigestUpdate(mdctx, mess2, strlen(mess2));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  printf("Digest %s is: ", DIGEST_NAME);
  for(i = 0; i < md_len; i++)
    printf("%02x", md_value[i]);
  printf("\n");

  /* Call this once before exit. */
  EVP_cleanup();
  exit(0);
}