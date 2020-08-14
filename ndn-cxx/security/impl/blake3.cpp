#include <string.h>
#include <openssl/evp.h>

#include "ndn-cxx/security/impl/blake3/blake3.h"

#define BLAKE3_DIGEST_LENGTH 32
#define NID_Blake3 1039
#define BLAKE_CBLOCK 1

static int digest_init(EVP_MD_CTX *ctx)
{
	puts("digest init");
	blake3_hasher_init((blake3_hasher*)EVP_MD_CTX_md_data(ctx));
	return 1;
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	puts("digest update");
	blake3_hasher_update((blake3_hasher*)EVP_MD_CTX_md_data(ctx), data, count);
	return 1;
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	puts("digest finalize");
	uint8_t blake3_md[BLAKE3_DIGEST_LENGTH];

	blake3_hasher_finalize((blake3_hasher*)EVP_MD_CTX_md_data(ctx), blake3_md, BLAKE3_DIGEST_LENGTH);
	memcpy(md, blake3_md, BLAKE3_DIGEST_LENGTH);
	return 1;
}


const EVP_MD* EVP_blake3()
{
    static EVP_MD *digest_meth = NULL;

    if (digest_meth == NULL) {
		puts("Make new meth");
		digest_meth = EVP_MD_meth_new(NID_Blake3, 9999);
		if (!digest_meth) {
			return digest_meth;
		}
		puts("set_result_size");
		if (!EVP_MD_meth_set_result_size(digest_meth, BLAKE3_DIGEST_LENGTH) ||
				!EVP_MD_meth_set_flags(digest_meth, 0) ||
				!EVP_MD_meth_set_init(digest_meth, digest_init) ||
				!EVP_MD_meth_set_update(digest_meth, digest_update) ||
				!EVP_MD_meth_set_final(digest_meth, digest_final) ||
				!EVP_MD_meth_set_cleanup(digest_meth, NULL) ||
				!EVP_MD_meth_set_ctrl(digest_meth, NULL) ||
				!EVP_MD_meth_set_input_blocksize(digest_meth, BLAKE_CBLOCK) ||
				!EVP_MD_meth_set_app_datasize(digest_meth, sizeof(EVP_MD*) + sizeof(blake3_hasher)) ||
				!EVP_MD_meth_set_copy(digest_meth, NULL)) {
			EVP_MD_meth_free(digest_meth);
			digest_meth = NULL;
		}
			
	}
	puts("all done");

	printf("Digest_meth : %p\n", (void *)digest_meth);
	return digest_meth;

}