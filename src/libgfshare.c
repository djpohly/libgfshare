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
  unsigned int sharecount;
  unsigned int threshold;
  unsigned int maxsize;
  unsigned char* coords;
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

static gfshare_ctx *
_gfshare_ctx_init_core( unsigned int sharecount,
                        unsigned char threshold,
                        unsigned int maxsize )
{
  gfshare_ctx *ctx;

  /* Size must be nonzero, and 1 <= threshold <= sharecount */
  if( maxsize < 1 || threshold < 1 || threshold > sharecount ) {
    errno = EINVAL;
    return NULL;
  }
  
  ctx = XMALLOC( sizeof(struct _gfshare_ctx) );
  if( ctx == NULL )
    return NULL; /* errno should still be set from XMALLOC() */
  
  ctx->sharecount = sharecount;
  ctx->threshold = threshold;
  ctx->maxsize = maxsize;
  ctx->coords = XMALLOC( sharecount );
  
  if( ctx->coords == NULL ) {
    int saved_errno = errno;
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  ctx->buffer = XMALLOC( sharecount * maxsize );
  
  if( ctx->buffer == NULL ) {
    int saved_errno = errno;
    XFREE( ctx->coords );
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  return ctx;
}

/* Initialise a gfshare context for producing shares */
gfshare_ctx *
gfshare_ctx_init_enc( unsigned int sharecount,
                      unsigned char threshold,
                      unsigned int maxsize )
{
  return _gfshare_ctx_init_core( sharecount, threshold, maxsize );
}

/* Initialise a gfshare context for recombining shares */
gfshare_ctx*
gfshare_ctx_init_dec( unsigned int sharecount,
                      unsigned int threshold,
                      unsigned int maxsize )
{
  return _gfshare_ctx_init_core( sharecount, threshold, maxsize );
}

/* Free a share context's memory. */
void 
gfshare_ctx_free( gfshare_ctx* ctx )
{
  gfshare_fill_rand( ctx->buffer, ctx->sharecount * ctx->maxsize );
  gfshare_fill_rand( ctx->coords, ctx->sharecount );
  XFREE( ctx->coords );
  XFREE( ctx->buffer );
  gfshare_fill_rand( (unsigned char*)ctx, sizeof(struct _gfshare_ctx) );
  XFREE( ctx );
}

/* --------------------------------------------------------[ Splitting ]---- */

/* Provide a secret to the encoder. (this re-scrambles the coefficients) */
void 
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
int
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

/* ----------------------------------------------------[ Recombination ]---- */

/* Provide a share context with shares.
 */
int
gfshare_ctx_dec_giveshares( gfshare_ctx* ctx,
                            unsigned int nshares,
                            unsigned char coords[static nshares],
                            unsigned int size,
                            unsigned char* pshares[static nshares] )
{
  unsigned int sharenr;
  for( sharenr = 0; sharenr < nshares; ++sharenr )
    memcpy( ctx->buffer + (sharenr * ctx->maxsize), pshares[sharenr], size );
  memcpy( ctx->coords, coords, nshares );
  return 0;
}

/* Extract the secret by interpolation of the shares.
 * secretbuf must be allocated and at least 'size' bytes long
 */
int
gfshare_ctx_dec_extract( const gfshare_ctx* ctx,
                         unsigned int size,
                         unsigned char secretbuf[static size],
                         unsigned int integrity )
{
  unsigned int i, j, k, ki, li;
  unsigned char *secret_ptr, *share_ptr;

  if( integrity < ctx->threshold || integrity > ctx->sharecount ) {
    errno = EINVAL;
    return 1;
  }

  /* Find indices at which we hit threshold and integrity parameter, accounting
   * for empty shares.  If not enough shares are provided, it is an error. */
  for( i = ki = 0; i < ctx->threshold && ki < ctx->sharecount; ++ki )
    if( ctx->coords[ki] != 0 )
      i++;
  if( i < ctx->threshold ) {
    errno = EINVAL;
    return 1;
  }

  /* At this point, i == ctx->threshold */
  for( li = ki; i < integrity && li < ctx->sharecount; ++li )
    if( ctx->coords[li] != 0 )
      i++;
  if( i < integrity ) {
    errno = EINVAL;
    return 1;
  }
  
  memset(secretbuf, 0, size);
  
  for( i = 0; i < ki; ++i ) {
    /* Compute L(i) as per Lagrange Interpolation */
    unsigned Li_top = 0, Li_bottom = 0;
    unsigned tops[ctx->sharecount];
    for( j = ki; j < li; ++j )
      tops[j] = 0;
    
    if( ctx->coords[i] == 0 ) continue; /* this share is not provided. */
    
    for( j = 0; j < ki; ++j ) {
      if( i == j ) continue;
      if( ctx->coords[j] == 0 ) continue; /* skip empty share */
      Li_top += logs[0 ^ ctx->coords[j]];
      for( k = ki; k < li; ++k )
        tops[k] += logs[ctx->coords[k] ^ ctx->coords[j]];
      Li_bottom += logs[(ctx->coords[i]) ^ (ctx->coords[j])];
    }
    Li_bottom %= 0xff;
    Li_top += 0xff - Li_bottom;
    Li_top %= 0xff;
    /* Li_top is now log(L(i)) */
    for( j = ki; j < li; ++j ) {
      tops[j] += 0xff - Li_bottom;
      tops[j] %= 0xff;
    }

    share_ptr = ctx->buffer + (ctx->maxsize * i);
    for( j = 0; j < size; ++j )
      if( share_ptr[j] ) {
        secretbuf[j] ^= exps[Li_top + logs[share_ptr[j]]];
        for( k = ki; k < li; ++k )
          ctx->buffer[ctx->maxsize * k + j] ^= exps[tops[k] + logs[share_ptr[j]]];
      }
  }
  for( i = ki; i < li; ++i )
    for( j = 0; j < size; ++j )
      if( ctx->buffer[ctx->maxsize * i + j] )
        return 1;
  return 0;
}
