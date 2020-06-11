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


typedef void (*gfshare_rand_func_t)(unsigned char*, unsigned int);

/* This will, by default, use random(). It's not very good so you should
 * replace it (perhaps with a function which reads from /dev/urandom).
 * If you can't be bothered, be sure to srandom() before you use the
 * gfshare_split function
 */
extern gfshare_rand_func_t gfshare_fill_rand;

/* --------------------------------------------------------[ Splitting ]---- */

/* Extract several shares from the provided secret.
 * Each 'pshares[i]' must be preallocated and at least 'size' bytes long.
 * 'coords' is an array of the coordinates of the shares you want.
 */
int gfshare_split(unsigned int /* size */,
                  unsigned char* /* secret */,
                  unsigned int /* threshold */,
                  unsigned int /* nshares */,
                  unsigned char* /* coords */,
                  unsigned char** /* pshares */);

/* ----------------------------------------------------[ Recombination ]---- */

/* Extract the secret by interpolation of the provided shares.
 * 'secret' must be allocated and at least 'size' bytes long
 */
int gfshare_recombine(unsigned int /* size */,
                      unsigned char* /* secret */,
                      unsigned int /* threshold */,
                      unsigned int /* nshares */,
                      unsigned char* /* coords */,
                      unsigned char** /* pshares */);

#endif /* LIBGFSHARE_H */
