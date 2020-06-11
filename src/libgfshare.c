/*
 * This file is Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include "config.h"
#include "libgfshare.h"
#include "libgfshare_tables.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define XMALLOC malloc
#define XFREE free

struct _gfshare_ctx {
  unsigned int maxshares;
  unsigned int threshold;
  unsigned int maxsize;
  unsigned char* buffer;
};

static void
_gfshare_fill_rand_using_random( unsigned char* buffer,
                                 unsigned int count )
{
  unsigned int i;
  for( i = 0; i < count; ++i )
    buffer[i] = (random() & 0xff00) >> 8; /* apparently the bottom 8 aren't
                                           * very random but the middles ones
                                           * are
                                           */
}

gfshare_rand_func_t gfshare_fill_rand = _gfshare_fill_rand_using_random;

/* ------------------------------------------------------[ Preparation ]---- */

gfshare_ctx *
gfshare_ctx_init( unsigned int maxshares,
                  unsigned char threshold,
                  unsigned int maxsize )
{
  gfshare_ctx *ctx;

  /* Size must be nonzero, and 1 <= threshold <= maxshares */
  if( maxsize < 1 || threshold < 1 || threshold > maxshares ) {
    errno = EINVAL;
    return NULL;
  }
  
  ctx = XMALLOC( sizeof(struct _gfshare_ctx) );
  if( ctx == NULL )
    return NULL; /* errno should still be set from XMALLOC() */
  
  ctx->maxshares = maxshares;
  ctx->threshold = threshold;
  ctx->maxsize = maxsize;
  
  ctx->buffer = XMALLOC( maxshares * maxsize );
  
  if( ctx->buffer == NULL ) {
    int saved_errno = errno;
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  return ctx;
}

/* Free a share context's memory. */
void 
gfshare_ctx_free( gfshare_ctx* ctx )
{
  gfshare_fill_rand( ctx->buffer, ctx->maxshares * ctx->maxsize );
  XFREE( ctx->buffer );
  gfshare_fill_rand( (unsigned char*)ctx, sizeof(struct _gfshare_ctx) );
  XFREE( ctx );
}

/* --------------------------------------------------------[ Splitting ]---- */

/* Provide a secret to the encoder. (this re-scrambles the coefficients) */
static void 
gfshare_ctx_enc_setsecret( gfshare_ctx* ctx,
                           unsigned int size,
                           const unsigned char secret[static size])
{
  memcpy( ctx->buffer + ((ctx->threshold-1) * ctx->maxsize),
          secret,
          size );
  gfshare_fill_rand( ctx->buffer, (ctx->threshold-1) * ctx->maxsize );
}

/* Extract a share from the context. 
 * 'share' must be preallocated and at least 'size' bytes long.
 * 'coord' is the coordinate of the share you want.
 */
static int
gfshare_ctx_enc_getshare( const gfshare_ctx* ctx,
                          unsigned char coord,
                          unsigned int size,
                          unsigned char share[static size])
{
  if (coord == 0) {
    errno = EINVAL;
    return 1;
  }
  unsigned int pos, coefficient;
  unsigned int ilog = logs[coord];
  unsigned char *coefficient_ptr = ctx->buffer;
  unsigned char *share_ptr;
  for( pos = 0; pos < size; ++pos )
    share[pos] = *(coefficient_ptr++);
  for( coefficient = 1; coefficient < ctx->threshold; ++coefficient ) {
    share_ptr = share;
    coefficient_ptr = ctx->buffer + coefficient * ctx->maxsize;
    for( pos = 0; pos < size; ++pos ) {
      unsigned char share_byte = *share_ptr;
      if( share_byte )
        share_byte = exps[ilog + logs[share_byte]];
      *share_ptr++ = share_byte ^ *coefficient_ptr++;
    }
  }
  return 0;
}

/* Extract several shares from the context.
 * Each element of 'pshares' must point to preallocated space that is at least
 *   'size' bytes long.
 * 'coords' is an array of the coordinates of the shares you want.
 */
static int
gfshare_ctx_enc_getshares( const gfshare_ctx* ctx,
                           unsigned int nshares,
                           unsigned char coords[static nshares],
                           unsigned int size,
                           unsigned char* pshares[static nshares])
{
  unsigned int sharenr;
  for( sharenr = 0; sharenr < nshares; ++sharenr )
    if (gfshare_ctx_enc_getshare(ctx, coords[sharenr], size, pshares[sharenr]))
      return 1;
  return 0;
}

/* Extract several shares from the provided secret.
 * Each 'pshares[i]' must be preallocated and at least 'size' bytes long.
 * 'coords' is an array of the coordinates of the shares you want.
 */
int gfshare_ctx_enc_split(gfshare_ctx* ctx,
                          unsigned int size,
                          unsigned char secret[static size],
                          unsigned int nshares,
                          unsigned char coords[static nshares],
                          unsigned char* pshares[static nshares])
{
  gfshare_ctx_enc_setsecret(ctx, size, secret);
  gfshare_ctx_enc_getshares(ctx, nshares, coords, size, pshares);
}

/* ----------------------------------------------------[ Recombination ]---- */

/* Extract the secret by interpolation of the provided shares.
 * coords must not contain any elements which are 0
 * secretbuf must be allocated and at least 'size' bytes long
 */
int
gfshare_ctx_dec_recombine( gfshare_ctx* ctx,
                           unsigned int nshares,
                           unsigned char coords[static nshares],
                           unsigned int size,
                           unsigned char* pshares[static nshares],
                           unsigned char secretbuf[static size])
{
  unsigned int i, j, k;
  unsigned char *secret_ptr, *share_ptr;

  if( nshares < ctx->threshold || nshares > ctx->maxshares ) {
    errno = EINVAL;
    return 1;
  }

  for( i = 0; i < nshares; ++i ) {
    if( coords[i] == 0 ) {
      errno = EINVAL;
      return 1;
    }
    memcpy( ctx->buffer + (i * ctx->maxsize), pshares[i], size );
  }
  
  memset(secretbuf, 0, size);
  
  for( i = 0; i < ctx->threshold; ++i ) {
    /* Compute L(i) as per Lagrange Interpolation */
    unsigned Li_top = 0, Li_bottom = 0;
    unsigned tops[ctx->maxshares];
    for( j = ctx->threshold; j < nshares; ++j )
      tops[j] = 0;
    
    for( j = 0; j < ctx->threshold; ++j ) {
      if( i == j ) continue;
      Li_top += logs[0 ^ coords[j]];
      for( k = ctx->threshold; k < nshares; ++k )
        tops[k] += logs[coords[k] ^ coords[j]];
      Li_bottom += logs[(coords[i]) ^ (coords[j])];
    }
    Li_bottom %= 0xff;
    Li_top += 0xff - Li_bottom;
    Li_top %= 0xff;
    /* Li_top is now log(L(i)) */
    for( j = ctx->threshold; j < nshares; ++j ) {
      tops[j] += 0xff - Li_bottom;
      tops[j] %= 0xff;
    }

    share_ptr = ctx->buffer + (ctx->maxsize * i);
    for( j = 0; j < size; ++j )
      if( share_ptr[j] ) {
        secretbuf[j] ^= exps[Li_top + logs[share_ptr[j]]];
        for( k = ctx->threshold; k < nshares; ++k )
          ctx->buffer[ctx->maxsize * k + j] ^= exps[tops[k] + logs[share_ptr[j]]];
      }
  }
  for( i = ctx->threshold; i < nshares; ++i )
    for( j = 0; j < size; ++j )
      if( ctx->buffer[ctx->maxsize * i + j] )
        return 1;
  return 0;
}
