/*-------------------------------------------------------------------------
 *
 * kmgr_utils.h
 *		Declarations for utility function for file encryption key
 *
 * Portions Copyright (c) 2020, PostgreSQL Global Development Group
 *
 * src/include/common/kmgr_utils.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef KMGR_UTILS_H
#define KMGR_UTILS_H

#include "common/cipher.h"

/* Current version number */
#define KMGR_VERSION 1

/*
 * Directories where cluster file encryption keys reside within PGDATA.
 */
#define KMGR_DIR			"pg_cryptokeys"
#define KMGR_DIR_PID		KMGR_DIR"/pg_alterckey.pid"
#define LIVE_KMGR_DIR		KMGR_DIR"/live"
/* used during cluster key rotation */
#define NEW_KMGR_DIR		KMGR_DIR"/new"
#define OLD_KMGR_DIR		KMGR_DIR"/old"

/* CryptoKey file name is keys id */
#define CryptoKeyFilePath(path, dir, id) \
	snprintf((path), MAXPGPATH, "%s/%d", (dir), (id))

/*
 * Identifiers of internal keys.
 */
#define KMGR_KEY_ID_REL 		0
#define KMGR_KEY_ID_WAL 		1
#define KMGR_MAX_INTERNAL_KEYS	2

/* We always, today, use a 256-bit AES key. */
#define KMGR_CLUSTER_KEY_LEN 	PG_AES256_KEY_LEN

/* double for hex format, plus some for spaces, \r,\n, and null byte */
#define ALLOC_KMGR_CLUSTER_KEY_LEN	(KMGR_CLUSTER_KEY_LEN * 2 + 10 + 2 + 1)

/* Maximum length of key the key manager can store */
#define KMGR_MAX_KEY_LEN			256
#define KMGR_MAX_KEY_LEN_BYTES		KMGR_MAX_KEY_LEN / 8


/*
 * Cryptographic key data structure.
 *
 * This is the structure we use to write out the encrypted keys and
 * which we use to store the keys in shared memory.
 *
 * Note that wrapping this structure results in an encrypted byte
 * string which is what we actually write and then read back in.
 *
 * klen is the key length in bytes
 * key is the encryption key of klen length
 */
typedef struct CryptoKey
{
	uint32		  klen;
	unsigned char key[KMGR_MAX_KEY_LEN_BYTES];
} CryptoKey;

extern bool kmgr_wrap_key(PgCipherCtx *ctx, CryptoKey *in, unsigned char *out, int *outlen);
extern bool kmgr_unwrap_key(PgCipherCtx *ctx, unsigned char *in, int inlen, CryptoKey *out);
extern bool kmgr_verify_cluster_key(unsigned char *cluster_key,
									unsigned char **in_keys, int *klens, CryptoKey *out_keys,
									int nkeys);
extern int	kmgr_run_cluster_key_command(char *cluster_key_command,
												char *buf, int size, char *dir);
extern int kmgr_get_cryptokeys(const char *path, unsigned char **keys, int *klens);

#endif							/* KMGR_UTILS_H */