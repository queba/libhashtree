#ifndef _HASHTREE_H
#define _HASHTREE_H

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

#include <inttypes.h>
#include <stdio.h>

enum {
  HASHTREE_DEFAULT_BLOCKSIZE  = 1024,
  HASHTREE_NAMESIZE   = 32,
  HASHTREE_KEYLEN     = 128
};

/* this struct holds the information for a hashtree invocation */
typedef struct hashtree_t {
  uint64_t   blocksize; /* size of digest block */
  uint64_t   blocks;  /* number of digest blocks */
  char     hashtype[HASHTREE_NAMESIZE]; /* hash name */
  void    *alg;   /* internal algorithm details */
  uint8_t    key[HASHTREE_KEYLEN]; /* key for hmac */
  uint32_t   keylen;  /* length of key */
  uint32_t   depth;   /* depth of tree */
} hashtree_t;

int HASHTREE_Init(hashtree_t *, const char *, const uint64_t, const uint64_t);
int HASHTREE_Keyneeded(hashtree_t *);
int HASHTREE_Setkey(hashtree_t *, const uint8_t *key, uint32_t keylen);
int HASHTREE_Data(hashtree_t *, const void *, size_t, uint8_t *);
size_t HASHTREE_Sumsize(hashtree_t *, size_t);
int HASHTREE_Print(hashtree_t *, FILE *, const char *, size_t, uint32_t,
    uint8_t *);
ssize_t HASHTREE_File(hashtree_t *, const char *, uint8_t **);
int HASHTREE_Range(hashtree_t *, size_t, size_t, size_t *, size_t *);
int HASHTREE_Depth(hashtree_t *, size_t);

#endif
