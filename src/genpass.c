//by posixninja, geohot, and chronic

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define BUF_SIZE 0x100000
#define SHA256_DIGEST_LENGTH 32

#define FLIPENDIAN(x) flip_endian((unsigned char*)(&(x)), sizeof(x))

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;

typedef struct {
  uint8 sig[8];
  uint32 version;
  uint32 enc_iv_size;
  uint32 unk1;
  uint32 unk2;
  uint32 unk3;
  uint32 unk4;
  uint32 unk5;
  uint8 uuid[16];
  uint32 blocksize;
  uint64 datasize;
  uint64 dataoffset;
} encrcdsa_header;

typedef struct {
  uint32 unk1;
  uint32 unk2;
  uint32 unk3;
  uint32 unk4;
  uint32 unk5;
} encrcdsa_block;

static inline void flip_endian(unsigned char* x, int length) {
  unsigned int i = 0;
  unsigned char tmp = '\0';
  for(i = 0; i < (length / 2); i++) {
    tmp = x[i];
    x[i] = x[length - i - 1];
    x[length - i - 1] = tmp;
  }
}

static inline uint64 u32_to_u64(uint32 msq, uint32 lsq) {
  uint64 ms = (uint64) msq;
  uint64 ls = (uint64) lsq;
  return ls | (ms << 32);
}

static uint64 hash_platform(const char* platform) {
  uint8 md[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char*) platform, strlen(platform), (unsigned char*) &md);

  uint64 hash = u32_to_u64(((md[0] << 24) | (md[1] << 16) | (md[2] << 8)
      | md[3]), ((md[4] << 24) | (md[5] << 16) | (md[6] << 8) | md[7]));

  return hash;
}

static uint64 ramdisk_size(const char* ramdisk) {
  struct stat filestat;
  if (stat(ramdisk, &filestat) < 0) {
    return 0;
  }
  return (uint64) filestat.st_size;
}

void print_hex(uint8* hex, int size) {
  int i = 0;
  for (i = 0; i < size; i++) {
    printf("%02x", hex[i]);
  }
  printf("\n");
}

int compare(const uint32* a, const uint32* b) {
  if (*a < *b)
    return -1;

  if (*a > *b)
    return 1;

  return 0;
}

uint8* generate_passphrase(const char* platform, const char* ramdisk) {
  SHA256_CTX ctx;
  uint64 salt[4];
  uint32 saltedHash[4];
  uint64 totalSize = ramdisk_size(ramdisk);
  uint64 platformHash = hash_platform(platform);

  salt[0] = u32_to_u64(0xad79d29d, 0xe5e2ac9e);
  salt[1] = u32_to_u64(0xe6af2eb1, 0x9e23925b);
  salt[2] = u32_to_u64(0x3f1375b4, 0xbd88815c);
  salt[3] = u32_to_u64(0x3bdff4e5, 0x564a9f87);

  FILE* fd = fopen(ramdisk, "rb");
  if (!fd) {
    fprintf(stderr, "error opening file: %s\n", ramdisk);
    return NULL;
  }

  int i = 0;
  for (i = 0; i < 4; i++) {
    salt[i] += platformHash;
    saltedHash[i] = ((uint32) (salt[i] % totalSize)) & 0xFFFFFE00;
  }
  qsort(&saltedHash, 4, 4, (int(*)(const void *, const void *)) &compare);

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, salt, 32);//SHA256_DIGEST_LENGTH);

  int count = 0;
  uint8* buffer = malloc(BUF_SIZE);
  uint8* passphrase = malloc(SHA256_DIGEST_LENGTH);
  while (count < totalSize) {
    unsigned int bytes = fread(buffer, 1, BUF_SIZE, fd);
    SHA256_Update(&ctx, buffer, bytes);

    for (i = 0; i < 4; i++) { //some salts remain
      if (count < saltedHash[i] && saltedHash[i] < (count + bytes)) {
        if ((saltedHash[i] + 0x4000) < count) {
          SHA256_Update(&ctx, buffer, saltedHash[i] - count);
				
        } else {
          SHA256_Update(&ctx, buffer + (saltedHash[i] - count), ((bytes
              - (saltedHash[i] - count)) < 0x4000) ? (bytes
              - (saltedHash[i] - count)) : 0x4000);
        }
      }
    }
    count += bytes;
  }

  fclose(fd);
  SHA256_Final(passphrase, &ctx);
  return passphrase;
}

uint8* decrypt_key(const char* filesystem, uint8* passphrase) {
  int i = 0;
  EVP_CIPHER_CTX ctx;
  uint8 data[0x30];
  int outlen, tmplen = 0;
  
  FILE* fd = fopen(filesystem, "rb");
  if (fd == NULL) {
    fprintf(stderr, "error opening file: %s", filesystem);
    return NULL;
  }
  
  uint8* buffer = (uint8*) malloc(BUF_SIZE);
  if(buffer == NULL) {
  	fprintf(stderr, "unable to allocate memory\n");
  	fclose(fd);
  	return NULL;
  }
  
  fread(buffer, 1, sizeof(encrcdsa_header), fd);
  
  uint32 blocks = 0;
  fread(&blocks, 1, sizeof(uint32), fd);
  FLIPENDIAN(blocks);
  
  fread(buffer, 1, sizeof(encrcdsa_block) * blocks, fd);
  fread(buffer, 1, 0x80, fd);
  
  uint32 skip = 0;
  fread(&skip, 1, sizeof(uint32), fd);
  FLIPENDIAN(skip);
  fread(buffer, 1, skip-3, fd);
		
  uint8* out = malloc(0x30);
  free(buffer);

  for (i = 0; i < 0x10; i++) {
    if (fread(data, 1, 0x30, fd) <= 0) {
      fprintf(stderr, "Error reading filesystem image");
      free(out);
      return NULL;
    }

    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, passphrase,
        &passphrase[24]);

    EVP_DecryptUpdate(&ctx, out, &outlen, data, 0x30);
    if (EVP_DecryptFinal_ex(&ctx, out + outlen, &tmplen)) {
      return out;
    }
    
    fseek(fd, 0x238, SEEK_CUR);
  }

  fclose(fd);
  return out;
}

int main(int argc, char* argv[]) {
  uint8* pass = NULL;
  uint8* key = NULL;

  if (argc < 3) {
    fprintf(stderr,
        "usage: genpass <platform> <ramdisk.dmg> <filesystem.dmg>\n");
    return -1;
  }

  char* platform = argv[1];
  char* ramdisk = argv[2];
  char* filesystem = argv[3];

  pass = generate_passphrase(platform, ramdisk);
  if (pass == NULL) {
    fprintf(stderr, "unable to generate asr passphrase\n");
    return -1;
  }
  printf("asr passphrase: ");
  print_hex(pass, 0x20);

  key = decrypt_key(filesystem, pass);
  if (key == NULL) {
    fprintf(stderr, "unable to decrypt vfdecrypt key\n");
    return -1;
  }
  printf("vfdecrypt key: ");
  print_hex(key, 0x24);

  if (pass)
    free(pass);
  if (key)
    free(key);

  return 0;
}
