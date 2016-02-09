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
  unsigned int size;
  unsigned char* sharenrs;
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
_gfshare_ctx_init_core( const unsigned char *sharenrs,
                        unsigned int sharecount,
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
  ctx->size = maxsize;
  ctx->sharenrs = XMALLOC( sharecount );
  
  if( ctx->sharenrs == NULL ) {
    int saved_errno = errno;
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  memcpy( ctx->sharenrs, sharenrs, sharecount );
  ctx->buffer = XMALLOC( sharecount * maxsize );
  
  if( ctx->buffer == NULL ) {
    int saved_errno = errno;
    XFREE( ctx->sharenrs );
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  return ctx;
}

/* Initialise a gfshare context for producing shares */
gfshare_ctx *
gfshare_ctx_init_enc( const unsigned char* sharenrs,
                      unsigned int sharecount,
                      unsigned char threshold,
                      unsigned int maxsize )
{
  unsigned int i;

  for (i = 0; i < sharecount; i++) {
    if (sharenrs[i] == 0) {
      /* can't have x[i] = 0 - that would just be a copy of the secret, in
       * theory (in fact, due to the way we use exp/log for multiplication and
       * treat log(0) as 0, it ends up as a copy of x[i] = 1) */
      errno = EINVAL;
      return NULL;
    }
  }

  return _gfshare_ctx_init_core( sharenrs, sharecount, threshold, maxsize );
}

/* Initialise a gfshare context for recombining shares */
gfshare_ctx*
gfshare_ctx_init_dec( const unsigned char* sharenrs,
                      unsigned int sharecount,
                      unsigned int threshold,
                      unsigned int maxsize )
{
  return _gfshare_ctx_init_core( sharenrs, sharecount, threshold, maxsize );
}

/* Set the current processing size */
int
gfshare_ctx_setsize( gfshare_ctx* ctx, unsigned int size )
{
  if( size < 1 || size >= ctx->maxsize ) {
    errno = EINVAL;
    return 1;
  }
  ctx->size = size;
  return 0;
}

/* Free a share context's memory. */
void 
gfshare_ctx_free( gfshare_ctx* ctx )
{
  gfshare_fill_rand( ctx->buffer, ctx->sharecount * ctx->maxsize );
  gfshare_fill_rand( ctx->sharenrs, ctx->sharecount );
  XFREE( ctx->sharenrs );
  XFREE( ctx->buffer );
  gfshare_fill_rand( (unsigned char*)ctx, sizeof(struct _gfshare_ctx) );
  XFREE( ctx );
}

/* --------------------------------------------------------[ Splitting ]---- */

/* Provide a secret to the encoder. (this re-scrambles the coefficients) */
void 
gfshare_ctx_enc_setsecret( gfshare_ctx* ctx,
                           const unsigned char* secret)
{
  memcpy( ctx->buffer + ((ctx->threshold-1) * ctx->maxsize),
          secret,
          ctx->size );
  gfshare_fill_rand( ctx->buffer, (ctx->threshold-1) * ctx->maxsize );
}

/* Extract a share from the context. 
 * 'share' must be preallocated and at least 'size' bytes long.
 * 'sharenr' is the index into the 'sharenrs' array of the share you want.
 */
int
gfshare_ctx_enc_getshare( const gfshare_ctx* ctx,
                          unsigned char sharenr,
                          unsigned char* share)
{
  if (sharenr >= ctx->sharecount) {
    errno = EINVAL;
    return 1;
  }
  unsigned int pos, coefficient;
  unsigned int ilog = logs[ctx->sharenrs[sharenr]];
  unsigned char *coefficient_ptr = ctx->buffer;
  unsigned char *share_ptr;
  for( pos = 0; pos < ctx->size; ++pos )
    share[pos] = *(coefficient_ptr++);
  for( coefficient = 1; coefficient < ctx->threshold; ++coefficient ) {
    share_ptr = share;
    coefficient_ptr = ctx->buffer + coefficient * ctx->maxsize;
    for( pos = 0; pos < ctx->size; ++pos ) {
      unsigned char share_byte = *share_ptr;
      if( share_byte )
        share_byte = exps[ilog + logs[share_byte]];
      *share_ptr++ = share_byte ^ *coefficient_ptr++;
    }
  }
  return 0;
}

/* ----------------------------------------------------[ Recombination ]---- */

/* Inform a recombination context of a change in share indexes */
void 
gfshare_ctx_dec_newshares( gfshare_ctx* ctx,
                           const unsigned char* sharenrs)
{
  memcpy( ctx->sharenrs, sharenrs, ctx->sharecount );
}

/* Provide a share context with one of the shares.
 * The 'sharenr' is the index into the 'sharenrs' array
 */
int
gfshare_ctx_dec_giveshare( gfshare_ctx* ctx,
                           unsigned char sharenr,
                           const unsigned char* share )
{
  if( sharenr >= ctx->sharecount ) {
    errno = EINVAL;
    return 1;
  }
  memcpy( ctx->buffer + (sharenr * ctx->maxsize), share, ctx->size );
  return 0;
}

/* Extract the secret by interpolation of the shares.
 * secretbuf must be allocated and at least 'size' bytes long
 */
int
gfshare_ctx_dec_extract( const gfshare_ctx* ctx,
                         unsigned char* secretbuf,
                         unsigned int integrity )
{
  unsigned int i, j, n, jn;
  unsigned char *secret_ptr, *share_ptr;

  if( integrity < ctx->threshold || integrity > ctx->sharecount ) {
    errno = EINVAL;
    return 1;
  }
  
  memset(secretbuf, 0, ctx->size);
  
  for( n = i = 0; n < ctx->threshold && i < ctx->sharecount; ++n, ++i ) {
    /* Compute L(i) as per Lagrange Interpolation */
    unsigned Li_top = 0, Li_bottom = 0;
    
    if( ctx->sharenrs[i] == 0 ) {
      n--;
      continue; /* this share is not provided. */
    }
    
    for( jn = j = 0; jn < ctx->threshold && j < ctx->sharecount; ++jn, ++j ) {
      if( i == j ) continue;
      if( ctx->sharenrs[j] == 0 ) {
        jn--;
        continue; /* skip empty share */
      }
      Li_top += logs[ctx->sharenrs[j]];
      Li_bottom += logs[(ctx->sharenrs[i]) ^ (ctx->sharenrs[j])];
    }
    Li_bottom %= 0xff;
    Li_top += 0xff - Li_bottom;
    Li_top %= 0xff;
    /* Li_top is now log(L(i)) */
    
    secret_ptr = secretbuf; share_ptr = ctx->buffer + (ctx->maxsize * i);
    for( j = 0; j < ctx->size; ++j ) {
      if( *share_ptr )
        *secret_ptr ^= exps[Li_top + logs[*share_ptr]];
      share_ptr++; secret_ptr++;
    }
  }
  return 0;
}
