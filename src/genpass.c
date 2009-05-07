//by posixninja, geohot, chronic, and #iphone-rce

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

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;

uint64 u32_to_u64(uint32 msq, uint32 lsq) {
	uint64 ms = (uint64) msq;
	uint64 ls = (uint64) lsq;
	return ls | (ms << 32);
}

uint64 hash_platform(const char* platform) {
	uint8 md[SHA_DIGEST_LENGTH];
	SHA1((const unsigned char*) platform, strlen(platform),
			(unsigned char*) &md);

	uint64 hash = u32_to_u64(((md[0] << 24) | (md[1] << 16) | (md[2] << 8)
			| md[3]), ((md[4] << 24) | (md[5] << 16) | (md[6] << 8) | md[7]));

	return hash;
}

uint64 ramdisk_size(const char* ramdisk) {
	struct stat filestat;
	if (stat(ramdisk, &filestat) < 0) {
		return 0;
	}
	return (uint64) filestat.st_size;
}

void keydump(uint8* key, int size) {
	int i = 0;
	for (i = 0; i < size; i++) {
		printf("%02x", key[i]);
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

int main(int argc, char* argv[]) {
	int i = 0;
	int read = 0;
	SHA256_CTX ctx;
	FILE* fd = NULL;
	uint64 salt[4];
	uint64 totalSize = 0;
	uint64 platformHash = 0;
	uint32 saltedHash[4];
	uint8* buffer = NULL;
	uint8* passphrase = NULL;

	if (argc < 3) {
		fprintf(stderr, "usage: genpass <platform> <ramdisk> <filesystem>\n");
		return -1;
	}

	totalSize = ramdisk_size(argv[2]);
	platformHash = hash_platform(argv[1]);

	salt[0] = u32_to_u64(0xad79d29d, 0xe5e2ac9e);
	salt[1] = u32_to_u64(0xe6af2eb1, 0x9e23925b);
	salt[2] = u32_to_u64(0x3f1375b4, 0xbd88815c);
	salt[3] = u32_to_u64(0x3bdff4e5, 0x564a9f87);

	fd = fopen(argv[2], "rb");
	if (!fd) {
		fprintf(stderr, "unable to open file %s\n", argv[2]);
		return -1;
	}

	for (i = 0; i < 4; i++) {
		salt[i] += platformHash;
		saltedHash[i] = ((uint32) (salt[i] % totalSize)) & 0xFFFFFE00;
	}

	qsort(&saltedHash, 4, 4, (int(*)(const void *, const void *)) &compare);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, salt, SHA256_DIGEST_LENGTH);

	i = 0; //hash count
	buffer = malloc(BUF_SIZE);
	passphrase = malloc(SHA256_DIGEST_LENGTH);
	int count = 0;
	while (count < totalSize) {
		read = fread(buffer, 1, BUF_SIZE, fd);
		SHA256_Update(&ctx, buffer, read);

		if (i < 4) { //some salts remain
			if (count >= (saltedHash[i] + 0x4000)) {
				i++;

			} else if (count < saltedHash[i] && saltedHash[i] < (count + read)) {
				if ((saltedHash[i] + 0x4000) < count) {
					SHA256_Update(&ctx, buffer, saltedHash[i] - count);

				} else {
					SHA256_Update(&ctx, buffer + (saltedHash[i] - count),
							((read - (saltedHash[i] - count)) < 0x4000) ? (read
									- (saltedHash[i] - count)) : 0x4000);
				}
			}
		}
		count += read;
	}

	fclose(fd);
	SHA256_Final(passphrase, &ctx);
	printf("passphrase: ");
	keydump(passphrase, SHA256_DIGEST_LENGTH);

	if (buffer) {
		free(buffer);
	}

	if (argc == 4) {
		fd = fopen(argv[3], "rb");
		EVP_CIPHER_CTX ctx;

		int offset = 0x1D4;
		uint8 data[0x30];
		uint8 out[0x30];
		int outlen, tmplen;
		int a;
		for (a = 0; a < 7; a++) {
			fseek(fd, offset, SEEK_SET);
			offset += 0x268;
			fread(data, 1, 0x30, fd);
			EVP_CIPHER_CTX_init(&ctx);
			EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, passphrase,
					&passphrase[24]);
			EVP_DecryptUpdate(&ctx, out, &outlen, data, 0x30);
			if (!EVP_DecryptFinal_ex(&ctx, out + outlen, &tmplen)) {
				printf("not block %d\n", a);
			} else {
				break;
			}
		}
		printf("vfdecryptk: ");
		keydump(out, 0x24);
	}

	if (passphrase)
		free(passphrase);

	return 0;
}
