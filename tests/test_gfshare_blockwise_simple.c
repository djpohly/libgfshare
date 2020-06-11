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

#include "libgfshare.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECRET_LEN 512

int
main( int argc, char **argv )
{
  int ok = 1, i;
  unsigned char* secret = malloc(SECRET_LEN);
  unsigned char* share1 = malloc(SECRET_LEN);
  unsigned char* share2 = malloc(SECRET_LEN);
  unsigned char* share3 = malloc(SECRET_LEN);
  unsigned char* recomb = malloc(SECRET_LEN);
  unsigned char coords[3];
  unsigned char* pshares[3];
  gfshare_ctx *G;
  
  /* Stage 1, make a secret */
  for( i = 0; i < SECRET_LEN; ++i )
    secret[i] = (random() & 0xff00) >> 8;
  /* Stage 2, split it three ways with a threshold of 2 */
  G = gfshare_ctx_init( 3, 2 );
  pshares[0] = share1; coords[0] = '0';
  pshares[1] = share2; coords[1] = '1';
  pshares[2] = share3; coords[2] = '2';
  gfshare_ctx_enc_split( G, SECRET_LEN, secret, 3, coords, pshares );
  gfshare_ctx_free( G );
  /* Prep the decode shape */
  G = gfshare_ctx_init( 3, 2 );
  /* Stage 3, attempt a recombination with shares 1 and 2 */
  pshares[0] = share1; coords[0] = '0';
  pshares[1] = share2; coords[1] = '1';
  if (gfshare_ctx_dec_recombine( G, 2, coords, SECRET_LEN, pshares, recomb ))
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 4, attempt a recombination with shares 1 and 3 */
  pshares[0] = share1; coords[0] = '0';
  pshares[1] = share3; coords[1] = '2';
  if (gfshare_ctx_dec_recombine( G, 2, coords, SECRET_LEN, pshares, recomb ))
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 5, attempt a recombination with shares 2 and 3 */
  pshares[0] = share2; coords[0] = '1';
  pshares[1] = share3; coords[1] = '2';
  if (gfshare_ctx_dec_recombine( G, 2, coords, SECRET_LEN, pshares, recomb ))
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 6, attempt a recombination with shares 1, 2 and 3 */
  pshares[0] = share1; coords[0] = '0';
  pshares[1] = share2; coords[1] = '1';
  pshares[2] = share3; coords[2] = '2';
  if (gfshare_ctx_dec_recombine( G, 3, coords, SECRET_LEN, pshares, recomb ))
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 7, attempt a recombination with shares 3, 2, and 1 */
  pshares[0] = share3; coords[0] = '2';
  pshares[1] = share2; coords[1] = '1';
  pshares[2] = share1; coords[2] = '0';
  if (gfshare_ctx_dec_recombine( G, 3, coords, SECRET_LEN, pshares, recomb ))
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 8, attempt a recombination with a bad share */
  pshares[0] = share1; coords[0] = '0';
  pshares[1] = share2; coords[1] = '1';
  pshares[2] = share3; coords[2] = '2';
  share2[3]++;
  if (!gfshare_ctx_dec_recombine( G, 3, coords, SECRET_LEN, pshares, recomb ))
    ok = 0;
  gfshare_ctx_free( G );
  free(recomb);
  free(share3);
  free(share2);
  free(share1);
  free(secret);
  return ok!=1;
}
