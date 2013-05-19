/* 

Copied from https://gitorious.org/bitcoin/libblkmaker/blobs/raw/master/base58.h

Copyright (c) 2012 Luke Dashjr

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#ifndef BLKMK_PRIVATE_H
#define BLKMK_PRIVATE_H

#include <stdbool.h>
#include <string.h>

// blkmaker.c
extern bool _blkmk_dblsha256(void *hash, const void *data, size_t datasz);

// hex.c
extern void _blkmk_bin2hex(char *out, const void *data, size_t datasz);
extern bool _blkmk_hex2bin(void *o, const char *x, size_t len);

// base58.c
bool _blkmk_b58tobin(void *bin, size_t binsz, const char *b58, size_t b58sz);
extern int _blkmk_b58check(void *bin, size_t binsz, const char *b58);

#endif