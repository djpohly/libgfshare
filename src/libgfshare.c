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

/* --------------------------------------------------------[ Splitting ]---- */

/* Extract several shares from the provided secret.
 * Each 'pshares[i]' must be preallocated and at least 'size' bytes long.
 * 'coords' is an array of the coordinates of the shares you want.
 */
int gfshare_split(unsigned int size,
                  unsigned char secret[static size],
                  unsigned int threshold,
                  unsigned int nshares,
                  unsigned char coords[static nshares],
                  unsigned char* pshares[static nshares])
{
  unsigned int sharenr;
  unsigned char buffer[nshares][size];

  memcpy( buffer[threshold - 1], secret, size );
  gfshare_fill_rand( buffer[0], (threshold - 1) * size );

  for( sharenr = 0; sharenr < nshares; ++sharenr ) {
    if (coords[sharenr] == 0) {
      errno = EINVAL;
      return 1;
    }
    unsigned int pos, coefficient;
    unsigned int ilog = logs[coords[sharenr]];
    unsigned char *coefficient_ptr = buffer[0];
    unsigned char *share_ptr;
    for( pos = 0; pos < size; ++pos )
      pshares[sharenr][pos] = *(coefficient_ptr++);
    for( coefficient = 1; coefficient < threshold; ++coefficient ) {
      share_ptr = pshares[sharenr];
      coefficient_ptr = buffer[coefficient];
      for( pos = 0; pos < size; ++pos ) {
        unsigned char share_byte = *share_ptr;
        if( share_byte )
          share_byte = exps[ilog + logs[share_byte]];
        *share_ptr++ = share_byte ^ *coefficient_ptr++;
      }
    }
  }
  return 0;
}

/* ----------------------------------------------------[ Recombination ]---- */

/* Extract the secret by interpolation of the provided shares.
 * coords must not contain any elements which are 0
 * 'secret' must be allocated and at least 'size' bytes long
 */
int
gfshare_recombine( unsigned int size,
                   unsigned char secret[static size],
                   unsigned int threshold,
                   unsigned int nshares,
                   unsigned char coords[static nshares],
                   unsigned char* pshares[static nshares])
{
  unsigned int i, j, k;
  unsigned char *secret_ptr, *share_ptr;
  unsigned char buffer[nshares][size];

  if( nshares < threshold ) {
    errno = EINVAL;
    return 1;
  }

  for( i = 0; i < nshares; ++i ) {
    if( coords[i] == 0 ) {
      errno = EINVAL;
      return 1;
    }
    memcpy( buffer[i], pshares[i], size );
  }
  
  memset(secret, 0, size);
  
  for( i = 0; i < threshold; ++i ) {
    /* Compute L(i) as per Lagrange Interpolation */
    unsigned Li_top = 0, Li_bottom = 0;
    unsigned tops[nshares];
    for( j = threshold; j < nshares; ++j )
      tops[j] = 0;
    
    for( j = 0; j < threshold; ++j ) {
      if( i == j ) continue;
      Li_top += logs[coords[j]];
      for( k = threshold; k < nshares; ++k )
        tops[k] += logs[coords[k] ^ coords[j]];
      Li_bottom += logs[coords[i] ^ coords[j]];
    }
    Li_bottom %= 0xff;
    Li_top += 0xff - Li_bottom;
    Li_top %= 0xff;
    /* Li_top is now log(L(i)) */
    for( j = threshold; j < nshares; ++j ) {
      tops[j] += 0xff - Li_bottom;
      tops[j] %= 0xff;
    }

    share_ptr = buffer[i];
    for( j = 0; j < size; ++j )
      if( share_ptr[j] ) {
        secret[j] ^= exps[Li_top + logs[share_ptr[j]]];
        for( k = threshold; k < nshares; ++k )
          buffer[k][j] ^= exps[tops[k] + logs[share_ptr[j]]];
      }
  }
  for( i = threshold; i < nshares; ++i )
    for( j = 0; j < size; ++j )
      if( buffer[i][j] )
        return 1;
  return 0;
}
