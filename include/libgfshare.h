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

#ifndef LIBGFSHARE_H
#define LIBGFSHARE_H


typedef struct _gfshare_ctx gfshare_ctx;

typedef void (*gfshare_rand_func_t)(unsigned char*, unsigned int);

/* This will, by default, use random(). It's not very good so you should
 * replace it (perhaps with a function which reads from /dev/urandom).
 * If you can't be bothered, be sure to srandom() before you use any
 * of the gfshare_ctx_enc_* functions
 */
extern gfshare_rand_func_t gfshare_fill_rand;

/* ------------------------------------------------------[ Preparation ]---- */

/* Initialise a gfshare context for producing shares */
gfshare_ctx* gfshare_ctx_init_enc(unsigned int /* sharecount */,
                                  unsigned char /* threshold */,
                                  unsigned int /* maxsize */);

/* Initialise a gfshare context for recombining shares */
gfshare_ctx* gfshare_ctx_init_dec(unsigned int /* sharecount */,
                                  unsigned int /* threshold */,
                                  unsigned int /* maxsize */);

/* Free a share context's memory. */
void gfshare_ctx_free(gfshare_ctx* /* ctx */);

/* --------------------------------------------------------[ Splitting ]---- */

/* Provide a secret to the encoder. (this re-scrambles the coefficients) */
void gfshare_ctx_enc_setsecret(gfshare_ctx* /* ctx */,
                               unsigned int /* size */,
                               const unsigned char* /* secret */);

/* Extract several shares from the context.
 * Each 'pshares[i]' must be preallocated and at least 'size' bytes long.
 * 'coords' is an array of the coordinates of the shares you want.
 */
int gfshare_ctx_enc_getshares(const gfshare_ctx* /* ctx */,
                              unsigned int /* nshares */,
                              unsigned char* /* coords */,
                              unsigned int /* size */,
                              unsigned char** /* pshares */);

/* ----------------------------------------------------[ Recombination ]---- */

/* Provide a share context with shares.
 */
int gfshare_ctx_dec_giveshares(gfshare_ctx* /* ctx */,
                               unsigned int /* nshares */,
                               unsigned char* /* coords */,
                               unsigned int /* size */,
                               unsigned char** /* pshares */);

/* Extract the secret by interpolation of the shares.
 * secretbuf must be allocated and at least 'size' bytes long
 */
int gfshare_ctx_dec_extract(const gfshare_ctx* /* ctx */,
                            unsigned int /* size */,
                            unsigned char* /* secretbuf */,
                            unsigned int /* integrity */);

#endif /* LIBGFSHARE_H */

