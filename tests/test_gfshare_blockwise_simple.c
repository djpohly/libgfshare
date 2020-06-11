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
  unsigned char* sharenrs = (unsigned char*)strdup("012");
  gfshare_ctx *G;
  
  /* Stage 1, make a secret */
  for( i = 0; i < SECRET_LEN; ++i )
    secret[i] = (random() & 0xff00) >> 8;
  /* Stage 2, split it three ways with a threshold of 2 */
  G = gfshare_ctx_init_enc( sharenrs, 3, 2, SECRET_LEN );
  gfshare_ctx_enc_setsecret( G, SECRET_LEN, secret );
  gfshare_ctx_enc_getshare( G, '0', SECRET_LEN, share1 );
  gfshare_ctx_enc_getshare( G, '1', SECRET_LEN, share2 );
  gfshare_ctx_enc_getshare( G, '2', SECRET_LEN, share3 );
  gfshare_ctx_free( G );
  /* Prep the decode shape */
  G = gfshare_ctx_init_dec( sharenrs, 3, 2, SECRET_LEN );
  /* Stage 3, attempt a recombination with shares 1 and 2 */
  sharenrs[2] = 0;
  gfshare_ctx_dec_newshares( G, sharenrs );
  gfshare_ctx_dec_giveshare( G, 0, SECRET_LEN, share1 );
  gfshare_ctx_dec_giveshare( G, 1, SECRET_LEN, share2 );
  if( gfshare_ctx_dec_extract( G, SECRET_LEN, recomb, 2 ) )
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 4, attempt a recombination with shares 1 and 3 */
  sharenrs[2] = '2';
  sharenrs[1] = 0;
  gfshare_ctx_dec_newshares( G, sharenrs );
  gfshare_ctx_dec_giveshare( G, 0, SECRET_LEN, share1 );
  gfshare_ctx_dec_giveshare( G, 2, SECRET_LEN, share3 );
  if( gfshare_ctx_dec_extract( G, SECRET_LEN, recomb, 2 ) )
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 5, attempt a recombination with shares 2 and 3 */
  sharenrs[0] = 0;
  sharenrs[1] = '1';
  gfshare_ctx_dec_newshares( G, sharenrs );
  gfshare_ctx_dec_giveshare( G, 1, SECRET_LEN, share2 );
  gfshare_ctx_dec_giveshare( G, 2, SECRET_LEN, share3 );
  if( gfshare_ctx_dec_extract( G, SECRET_LEN, recomb, 2 ) )
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 6, attempt a recombination with shares 1, 2 and 3 */
  sharenrs[0] = '0';
  gfshare_ctx_dec_newshares( G, sharenrs );
  gfshare_ctx_dec_giveshare( G, 0, SECRET_LEN, share1 );
  gfshare_ctx_dec_giveshare( G, 1, SECRET_LEN, share2 );
  gfshare_ctx_dec_giveshare( G, 2, SECRET_LEN, share3 );
  if( gfshare_ctx_dec_extract( G, SECRET_LEN, recomb, 3 ) )
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 7, attempt a recombination with shares 3, 2, and 1 */
  sharenrs[0] = '2';
  sharenrs[2] = '0';
  gfshare_ctx_dec_newshares( G, sharenrs );
  gfshare_ctx_dec_giveshare( G, 0, SECRET_LEN, share3 );
  gfshare_ctx_dec_giveshare( G, 1, SECRET_LEN, share2 );
  gfshare_ctx_dec_giveshare( G, 2, SECRET_LEN, share1 );
  if( gfshare_ctx_dec_extract( G, SECRET_LEN, recomb, 3 ) )
    ok = 0;
  if( memcmp(secret, recomb, SECRET_LEN) )
    ok = 0;
  /* Stage 8, attempt a recombination with a bad share */
  sharenrs[0] = '0';
  sharenrs[2] = '2';
  share2[3]++;
  gfshare_ctx_dec_newshares( G, sharenrs );
  gfshare_ctx_dec_giveshare( G, 0, SECRET_LEN, share1 );
  gfshare_ctx_dec_giveshare( G, 1, SECRET_LEN, share2 );
  gfshare_ctx_dec_giveshare( G, 2, SECRET_LEN, share3 );
  if( !gfshare_ctx_dec_extract( G, SECRET_LEN, recomb, 3 ) )
    ok = 0;
  gfshare_ctx_free( G );
  free(sharenrs);
  free(recomb);
  free(share3);
  free(share2);
  free(share1);
  free(secret);
  return ok!=1;
}
