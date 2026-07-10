#ifndef AES_H
#define AES_H

/* Single-block AES-128 encryption */
void aes128_encrypt_block(const unsigned char key[16],
			  const unsigned char in[16],
			  unsigned char out[16]);

/* AES-128-GCM authenticated encryption */
int aes128_gcm_encrypt(const unsigned char key[16],
		       const unsigned char iv[12],
		       const unsigned char *aad, int aad_len,
		       const unsigned char *pt, int pt_len,
		       unsigned char *ct, unsigned char tag[16]);

/* AES-128-GCM authenticated decryption */
int aes128_gcm_decrypt(const unsigned char key[16],
		       const unsigned char iv[12],
		       const unsigned char *aad, int aad_len,
		       const unsigned char *ct, int ct_len,
		       unsigned char *pt, const unsigned char tag[16]);

#endif