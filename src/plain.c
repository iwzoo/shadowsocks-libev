#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define CIPHER_UNSUPPORTED "unsupported"

#include "ppbloom.h"
#include "plain.h"
#include "utils.h"

#define PLAIN "plain"

void
dump0(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", (uint8_t)text[i]);
    printf("\n");
}

int
plain_encrypt_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
	cipher_ctx_t cipher_ctx;
	plain_ctx_init(cipher, &cipher_ctx, 1);


	static buffer_t tmp = {0, 0, 0, NULL };
	brealloc(&tmp, cipher->key_len + plaintext->len + sizeof(cipher->key_len), capacity);
	buffer_t *ciphertext = &tmp;
	ciphertext->len = cipher->key_len + plaintext->len + sizeof(cipher->key_len);
	memcpy(ciphertext->data, &cipher->key_len, sizeof(cipher->key_len));
	memcpy(ciphertext->data + sizeof(cipher->key_len), cipher->key, cipher->key_len); 
	memcpy(ciphertext->data + sizeof(cipher->key_len) + cipher->key_len, plaintext->data, plaintext->len);

	brealloc(plaintext, ciphertext->len, capacity);
	memcpy(plaintext->data, ciphertext->data, ciphertext->len);
	plaintext->len = ciphertext->len;

	plain_ctx_release(&cipher_ctx);

	return CRYPTO_OK;	
}

int
plain_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{

	if( cipher_ctx==NULL )
		return CRYPTO_ERROR;

	if( cipher_ctx->init==1 ) return CRYPTO_OK;
	cipher_ctx->init = 1;
	cipher_t * cipher = cipher_ctx->cipher;

	static buffer_t tmp = {0, 0, 0, NULL };
	brealloc(&tmp, cipher->key_len + plaintext->len + sizeof(cipher->key_len), capacity);
	buffer_t *ciphertext = &tmp;
	ciphertext->len = cipher->key_len + plaintext->len + sizeof(cipher->key_len);
	memcpy(ciphertext->data, &cipher->key_len, sizeof(cipher->key_len));
	memcpy(ciphertext->data + sizeof(cipher->key_len), cipher->key, cipher->key_len); 
	memcpy(ciphertext->data + sizeof(cipher->key_len) + cipher->key_len, plaintext->data, plaintext->len);

	brealloc(plaintext, ciphertext->len, capacity);
	memcpy(plaintext->data, ciphertext->data, ciphertext->len);
	plaintext->len = ciphertext->len;


	return CRYPTO_OK;
}

int
plain_decrypt_all(buffer_t *ciphertext, cipher_t *cipher, size_t capacity)
{
	size_t key_len = cipher->key_len + sizeof(cipher->key_len);
	if( ciphertext->len <= key_len ){
		return CRYPTO_ERROR;
	}
	cipher_ctx_t cipher_ctx;
	plain_ctx_init(cipher, &cipher_ctx, 0);
	
	static buffer_t tmp = {0, 0, 0, NULL};
	brealloc(&tmp, ciphertext->len, capacity);
	buffer_t* plaintext = &tmp;
	plaintext->len = ciphertext->len - key_len;

	size_t* key_len_data = (size_t*)ciphertext->data;
	uint8_t* key = (uint8_t*)(ciphertext->data + sizeof(cipher->key_len));
	if( *key_len_data != cipher->key_len || memcmp(key, cipher->key, *key_len_data) ){

		LOGE("crypto-a: plain-a: unknown ciphertext");
		LOGI("key length: %d\t cipher key length: %d", (int)*key_len_data, (int)cipher->key_len);
		// release cipher_ctx??
		return CRYPTO_ERROR;
	}
	plain_ctx_release(&cipher_ctx);

	memcpy(plaintext->data, ciphertext->data + key_len, ciphertext->len - key_len );
	
	brealloc(ciphertext, plaintext->len , capacity);
	memcpy(ciphertext->data, plaintext->data, plaintext->len  );
	ciphertext->len = plaintext->len;

	return CRYPTO_OK;
}

int
plain_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
	if( cipher_ctx==NULL ) 
		return CRYPTO_ERROR;
	if( cipher_ctx->init==1 ) return CRYPTO_OK;
	cipher_ctx->init = 1;

	cipher_t* cipher = cipher_ctx->cipher;

	size_t key_len = cipher->key_len + sizeof(cipher->key_len);
	if( ciphertext->len <= key_len ){
		LOGI("cipher length: %ld", ciphertext->len);
		return CRYPTO_ERROR;
	}
	static buffer_t tmp = {0, 0, 0, NULL};
	brealloc(&tmp, ciphertext->len, capacity);
	buffer_t* plaintext = &tmp;
	plaintext->len = ciphertext->len - key_len;

	size_t* key_len_data = (size_t*)ciphertext->data;
	uint8_t* key = (uint8_t*)(ciphertext->data + sizeof(cipher->key_len));
	if( *key_len_data != cipher->key_len || memcmp(key, cipher->key, *key_len_data) ){
		LOGE("crypto: plain: unknown ciphertext");
		LOGI("key length: %d\t cipher key length: %d", (int)*key_len_data, (int)cipher->key_len);
		LOGI("key: %s\t read key: %s#", (const char*)cipher->key, (const char*)key );
		dump0("plain", ciphertext->data, ciphertext->len);
		// release cipher_ctx??
		return CRYPTO_ERROR;
	}
	memcpy(plaintext->data, ciphertext->data + key_len, ciphertext->len - key_len );
	
	brealloc(ciphertext, plaintext->len , capacity);
	memcpy(ciphertext->data, plaintext->data, plaintext->len );
	ciphertext->len = plaintext->len ;
	

	return CRYPTO_OK;
}

void
plain_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc)
{
	cipher_ctx->cipher = cipher;
	cipher_ctx->init = 1;
	if( enc ){
		rand_bytes(cipher_ctx->nonce, cipher->nonce_len);
	}
}

void
plain_ctx_release(cipher_ctx_t* cipher_ctx)
{
	cipher_ctx->init = 0;
}

cipher_t *
plain_init(const char *pass, const char *key, const char *method)
{
	if( strcmp(method, PLAIN) ){
		LOGE("unknown encrypt method: %s", method);
		return NULL;
	}
	cipher_t* cipher = (cipher_t*)ss_malloc(sizeof(cipher_t));
	memset(cipher, 0, sizeof(cipher_t));
	if( key != NULL ){
		LOGI("constructing key as cipher key...");
		cipher->key_len = min(strlen(key), MAX_KEY_LENGTH-1);
		memcpy(cipher->key, key, cipher->key_len); 
	} else if( pass !=NULL ){
		LOGI("constructing password as cipher key...");
		cipher->key_len = min(strlen(pass), MAX_KEY_LENGTH-1);
		memcpy(cipher->key, pass, cipher->key_len);
	}
	if( cipher->key_len==0 ){
		FATAL("Key or password must be specified");
	}
	return cipher;
}
