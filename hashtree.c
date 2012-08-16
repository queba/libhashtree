/*
 * Copyright (c) 2011 Alistair Crooks <agc@@NetBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/md5.h>
//#include <rmd160.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "hashtree.h"

enum {
  MAX_LEVEL   = 8
};

#ifndef USE_ARG
#define USE_ARG(x)       /*LINTED*/(void)&(x)
#endif

#ifndef howmany
#define howmany(x, y)   (((x)+((y)-1))/(y))
#endif

/* print raw checksum info */
static void
praw(FILE *fp, const uint8_t *raw, size_t hashsize)
{
  size_t    i;

  for (i = 0 ; i < hashsize ; i++) {
    (void) fprintf(fp, "%02x", raw[i]);
  }
}

/* perform an md5 digest of a block */
static int
md5block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  MD5_CTX ctx;

  USE_ARG(tree);
  (void) memset(&ctx, 0x0, sizeof(ctx));
  MD5Init(&ctx);
  MD5Update(&ctx, (const uint8_t *)data, (unsigned)size);
  MD5Final(raw, &ctx);
  return 16;
}

/* perform an rmd160 digest of a block */
#if 0
static int
rmd160block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  RMD160_CTX  ctx;

  USE_ARG(tree);
  (void) memset(&ctx, 0x0, sizeof(ctx));
  RMD160Init(&ctx);
  RMD160Update(&ctx, (const uint8_t *)data, (unsigned)size);
  RMD160Final(raw, &ctx);
  return 20;
}
#endif

/* perform an sha1 digest of a block */
static int
sha1block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  SHA_CTX  ctx;

  USE_ARG(tree);
  (void) memset(&ctx, 0x0, sizeof(ctx));
  SHA0Init(&ctx);
  SHA1Update(&ctx, (const uint8_t *)data, (unsigned)size);
  SHA1Final(raw, &ctx);
  return 20;
}

/* perform an sha256 digest of a block */
static int
sha256block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  SHA256_CTX  ctx;

  USE_ARG(tree);
  (void) memset(&ctx, 0x0, sizeof(ctx));
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, (const uint8_t *)data, size);
  SHA256_Final(raw, &ctx);
  return 32;
}

/* perform an sha512 digest of a block */
static int
sha512block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  SHA512_CTX  ctx;

  USE_ARG(tree);
  (void) memset(&ctx, 0x0, sizeof(ctx));
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, (const uint8_t *)data, size);
  SHA512_Final(raw, &ctx);
  return 64;
}

/* perform an hmac sha512 digest of a block */
#if 0
static int
hmacmd5block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  hmac("md5", tree->key, (size_t)tree->keylen, (const uint8_t *)data,
    size, raw, HMAC_MAX_DIGEST_SIZE);
  return 16;
}

/* perform an hmac sha512 digest of a block */
static int
hmacrmd160block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  hmac("rmd160", tree->key, (size_t)tree->keylen, (const uint8_t *)data,
    size, raw, HMAC_MAX_DIGEST_SIZE);
  return 20;
}

/* perform an hmac sha512 digest of a block */
static int
hmacsha1block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  hmac("sha1", tree->key, (size_t)tree->keylen, (const uint8_t *)data,
    size, raw, HMAC_MAX_DIGEST_SIZE);
  return 20;
}

/* perform an hmac sha512 digest of a block */
static int
hmacsha256block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  hmac("sha256", tree->key, (size_t)tree->keylen, (const uint8_t *)data,
    size, raw, HMAC_MAX_DIGEST_SIZE);
  return 32;
}

/* perform an hmac sha512 digest of a block */
static int
hmacsha512block(hashtree_t *tree, const char *data, size_t size, uint8_t *raw)
{
  hmac("sha512", tree->key, (size_t)tree->keylen, (const uint8_t *)data,
    size, raw, HMAC_MAX_DIGEST_SIZE);
  return 64;
}
#endif

/* structure to describe a digest algorithm */
typedef struct hashalg_t {
  const char  *name;  /* alg name */
  size_t     size;  /* raw digest size in bytes */
  const int  keyneeded; /* needs a key to work */
  int   (*hashfunc)(hashtree_t *, const char *, size_t, uint8_t *);
} hashalg_t;

static hashalg_t  algs[] = {
  { "md5",    16, 0,  md5block  },
  { "sha1",   20, 0,  sha1block },
  { "sha256", 32, 0,  sha256block },
  { "sha512", 64, 0,  sha512block },
/*
  { "rmd160", 20, 0,  rmd160block },
  { "hmacmd5",  16, 1,  hmacmd5block  },
  { "hmacrmd160", 20, 1,  hmacrmd160block },
  { "hmacsha1", 20, 1,  hmacsha1block },
  { "hmacsha256", 32, 1,  hmacsha256block },
  { "hmacsha512", 64, 1,  hmacsha512block },
*/
  { NULL,   0,  0,  NULL    }
};

/* find an algorithm */
static hashalg_t *
findalg(const char *name)
{
  hashalg_t *alg;

  for (alg = algs ; alg->name ; alg++) {
    if (strcasecmp(name, alg->name) == 0) {
      return alg;
    }
  }
  return NULL;
}

/* print the whole hash tree */
static int
ptree(hashtree_t *tree, FILE *fp, size_t size, uint32_t top, uint8_t *out)
{
  hashalg_t *alg;
  size_t     rawoff;
  size_t     blockc;

  blockc = howmany(size, tree->blocksize);
  alg = tree->alg;
  rawoff = blockc * alg->size;
  if (blockc > 1) {
    ptree(tree, fp, (size_t)(blockc * alg->size), top, &out[rawoff]);
  }
  if (fp != NULL) {
    praw(fp, out, rawoff);
  }
  return 1;
}

/* return the total number of bytes which will be needed */
static size_t
sumsize(hashtree_t *tree, size_t size, size_t total)
{
  hashalg_t *alg;
  size_t     blockc;

  if (tree->blocksize == 0) {
    blockc = tree->blocks;
  } else {
    blockc = howmany(size, tree->blocksize);
  }
  alg = tree->alg;
  total += (blockc * alg->size);
  if (blockc == 1) {
    return total;
  }
  return sumsize(tree, blockc * alg->size, total);
}

/***************************************************************************/

/* initialise the hash tree */
int
HASHTREE_Init(hashtree_t *tree, const char *hash, const uint64_t blocksize,
  const uint64_t blocks)
{
  hashalg_t *alg;
  uint64_t   blksz;

  if ((blksz = blocksize) == 0 && blocks == 0) {
    blksz = HASHTREE_DEFAULT_BLOCKSIZE;
  }
  if ((alg = findalg(hash)) == NULL) {
    (void) fprintf(stderr, "bad algorithm '%s'\n", hash);
    return 0;
  }
  tree->blocksize = blksz;
  tree->blocks = blocks;
  tree->alg = alg;
  (void) snprintf(tree->hashtype, sizeof(tree->hashtype), "%s", hash);
  return 1;
}

/* remember the key in our hashtree structure */
int
HASHTREE_Setkey(hashtree_t *tree, const uint8_t *key, uint32_t keylen)
{
  tree->keylen = (uint32_t)MIN(sizeof(tree->key), keylen);
  (void) memcpy(tree->key, key, tree->keylen);
  return (keylen == tree->keylen);
}

/* calculate hashtree on a string of data */
int
HASHTREE_Data(hashtree_t *tree, const void *vdata, size_t size, uint8_t *out)
{
  const char  *data = (const char *)vdata;
  hashalg_t *alg;
  size_t     rawoff;
  size_t     blockc;
  size_t     bytes;
  size_t     cc;

  if (tree->blocksize == 0) {
    tree->blocksize = howmany(size, tree->blocks);
    blockc = tree->blocks;
  } else {
    tree->blocks = blockc = howmany(size, tree->blocksize);
  }
  alg = tree->alg;
  for (rawoff = 0, cc = 0 ; cc < size ; cc += bytes) {
    bytes = MIN(tree->blocksize, (size - cc));
    rawoff += (*alg->hashfunc)(tree, &data[cc], bytes, &out[rawoff]);
  }
  if (blockc > 1) {
    tree->depth += 1;
    HASHTREE_Data(tree, (const char *)out,
      (size_t)(blockc * alg->size), &out[rawoff]);
  }
  return 1;
}

/* return the size in bytes that the hash tree needs */
size_t
HASHTREE_Sumsize(hashtree_t *tree, size_t size)
{
  return sumsize(tree, size, 0);
}

/* return 1 if a key is needed */
int
HASHTREE_Keyneeded(hashtree_t *tree)
{
  hashalg_t *alg;

  alg = tree->alg;
  return alg->keyneeded;
}

/* print the whole hash tree */
int
HASHTREE_Print(hashtree_t *tree, FILE *fp, const char *f, size_t size, uint32_t top, uint8_t *out)
{
  hashalg_t *alg;

  alg = tree->alg;
  if (f && fp != NULL) {
    (void) fprintf(fp, "HASHTREE/%s/%u/%zu/%" PRIu64 " (%s) = ",
      alg->name, (top) ? top : tree->depth + 1, size, tree->blocksize, f);
  }
  ptree(tree, fp, size, top, out);
  if (fp != NULL) {
    (void) fprintf(fp, "\n");
  }
  return 1;
}

/* calculate a hash tree on a file, returning size of sum */
ssize_t
HASHTREE_File(hashtree_t *tree, const char *f, uint8_t **out)
{
  struct stat  st;
  uint8_t   *msg;
  size_t     size;
  size_t     ret;
  FILE    *fp;

  if ((fp = fopen(f, "r")) == NULL) {
    (void) fprintf(stderr, "hmac: can't open '%s'\n", f);
    return -1;
  }
  (void) fstat(fileno(fp), &st);
  size = (size_t)st.st_size;
  msg = mmap(NULL, size, PROT_READ, MAP_FILE, fileno(fp), 0);
  if (msg == MAP_FAILED) {
    (void) fprintf(stderr, "hmac: mmap failed '%s'\n", f);
    return -1;
  }
  ret = HASHTREE_Sumsize(tree, size);
  *out = calloc(1, ret);
  HASHTREE_Data(tree, msg, size, *out);
  munmap(msg, (size_t)st.st_size);
  (void) fclose(fp);
  return (ssize_t)size;
}

/* given a byte offset from the start of string, work out the range of the block */
int
HASHTREE_Range(hashtree_t *tree, size_t off, size_t size, size_t *from,
  size_t *to)
{
  hashalg_t *alg;
  size_t     span;

  alg = tree->alg;
  for (span = tree->blocksize;
       (*from = (off / alg->size) * span) > size;
       span *= tree->blocksize) {
    /* higher level */
    
  }
  *to = *from + span;
  return 1;
}

/* return the depth of the tree */
int
HASHTREE_Depth(hashtree_t *tree, size_t size)
{
  uint64_t  b;
  int   i;

  for (b = tree->blocksize, i = 1;
       i < MAX_LEVEL ;
       b *= tree->blocksize, i++) {
    if (size <= b) {
      return i;
    }
  }
  return MAX_LEVEL;
}

