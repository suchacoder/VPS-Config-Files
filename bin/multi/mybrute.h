/*

MyBrute
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org

    Copyright 2005,2006 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl.txt
*/

#include <stdio.h>
#include <stdlib.h>


#if !defined(u_char)
    typedef unsigned char   u_char;
#endif

typedef int (*mybrute_wordfunc_t)(/* mybrute_t */ void *, FILE *);
// I can't use mybrute_t since it's declared later
// and I cannot place this typedef later because mybrute_t uses it

typedef struct {
    int     bufflen;                // length of the buffer
    int     wordlen;                // wordlist length counter
    u_char  table[256];             // brute forcing table
    u_char  *buff;                  // our magic buffer with the result
    u_char  **tp;                   // table pointer for each char of buff
    mybrute_wordfunc_t  wordfunc;   // wordlist type
} mybrute_t;



enum {      // 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 ...
    MYBRUTE_WORD_NONE     = 1,  // normal, the text is used as is
    MYBRUTE_WORD_AUTOCASE = 2,  // aa = aa Aa AA
    MYBRUTE_WORD_UPPER    = 4,  // aA = AA
    MYBRUTE_WORD_LOWER    = 8,  // aA = aa
};



mybrute_t *mybrute_init(int bufflen, u_char *table);
int mybrute(mybrute_t *brute, int pos);
int mybrute_options(mybrute_t *brute, int option);
int mybrute_word(mybrute_t *brute, FILE *fd);
void mybrute_restore(mybrute_t *brute);
void mybrute_free(mybrute_t *brute);
