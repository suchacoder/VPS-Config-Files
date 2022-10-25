/*

MyBrute 0.2
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

#include "mybrute.h"



#define WORDLIST_READ(INSTRUCTIONS)                             \
    int     chr;                                                \
    u_char  *p;                                                 \
                                                                \
redo:                                                           \
    if(!fgets((char *)brute->buff, brute->bufflen + 1, fd)) {   \
        return(0);                                              \
    }                                                           \
                                                                \
    for(p = brute->buff; (chr = *p); p++) {                     \
        if((chr == '\r') || (chr == '\n')) break;               \
        INSTRUCTIONS;                                           \
    }                                                           \
                                                                \
    if(p == brute->buff) goto redo;                             \
                                                                \
    if(!*p) {                                                   \
        do {                                                    \
            chr = fgetc(fd);                                    \
        } while((chr >= 0) && (chr != '\n'));                   \
    }                                                           \
                                                                \
    *p = 0;                                                     \
    brute->wordlen = p - brute->buff;                           \
                                                                \
    return(1);



int mybrute_word_none(mybrute_t *brute, FILE *fd) {
    WORDLIST_READ(
    )
}



int mybrute_word_scancase(mybrute_t *brute, int pos) {
    u_char   chr;

    if(pos == brute->wordlen) return(0);
    chr = brute->buff[pos];

    if((chr >= 'A') && (chr <= 'Z')) {
        brute->buff[pos] = chr | 32;
        if(!mybrute_word_scancase(brute, pos + 1)) return(0);

    } else if((chr >= 'a') && (chr <= 'z')) {
        brute->buff[pos] = chr ^ 32;

    } else {
        if(!mybrute_word_scancase(brute, pos + 1)) return(0);
    }

    return(1);
}



int mybrute_word_autocase(mybrute_t *brute, FILE *fd) {
    if(mybrute_word_scancase(brute, 0)) return(1);

    WORDLIST_READ(
        if((chr >= 'A') && (chr <= 'Z')) *p = chr | 32;
        // we must first make everything lower case
    )
}



int mybrute_word_upper(mybrute_t *brute, FILE *fd) {
    WORDLIST_READ(
        if((chr >= 'a') && (chr <= 'z')) *p = chr ^ 32;
    )
}



int mybrute_word_lower(mybrute_t *brute, FILE *fd) {
    WORDLIST_READ(
        if((chr >= 'A') && (chr <= 'Z')) *p = chr | 32;
    )
}



mybrute_t *mybrute_init(int bufflen, u_char *table) {
    mybrute_t   *brute;
    int     i;
    u_char  *t;

    brute = malloc(sizeof(mybrute_t));
    if(!brute) return(NULL);

    brute->bufflen = bufflen++;

    brute->buff = calloc(bufflen, sizeof(u_char));
    if(!brute->buff) {
        free(brute);
        return(NULL);
    }

    brute->tp = malloc(bufflen * sizeof(u_char *));
    if(!brute->tp) {
        free(brute->buff);
        free(brute);
        return(NULL);
    }

    for(i = 0; i < brute->bufflen; i++) {
        brute->tp[i] = brute->table;
    }

    for(t = brute->table; (i = *table); table++) {
        for(table++; i <= *table; t++, i++) {
            *t = i;
        }
    }
    *t = 0;

    brute->wordlen = 0;

    brute->wordfunc = (void *)mybrute_word_none;

    return(brute);
}



int mybrute(mybrute_t *brute, int pos) {
    if(pos == brute->bufflen) return(0);
    if(!*brute->tp[pos]) {
        brute->tp[pos] = brute->table;
        if(!mybrute(brute, pos + 1)) return(0);
    }
    brute->buff[pos] = *brute->tp[pos];
    brute->tp[pos]++;
    return(1);
}



int mybrute_options(mybrute_t *brute, int option) {
    if(option & MYBRUTE_WORD_NONE) {
        brute->wordfunc = (void *)mybrute_word_none;
    }
    if(option & MYBRUTE_WORD_AUTOCASE) {
        brute->wordfunc = (void *)mybrute_word_autocase;
    }
    if(option & MYBRUTE_WORD_UPPER) {
        brute->wordfunc = (void *)mybrute_word_upper;
    }
    if(option & MYBRUTE_WORD_LOWER) {
        brute->wordfunc = (void *)mybrute_word_lower;
    }
    return(1);
}



int mybrute_word(mybrute_t *brute, FILE *fd) {
    return(brute->wordfunc(brute, fd));
}



void mybrute_restore(mybrute_t *brute) {
    int     i,
            chr;
    u_char  *p;

    for(i = 0; i < brute->bufflen; i++) {
        brute->tp[i] = brute->table;
        chr = brute->buff[i];
        if(!chr) {
            for(++i; i < brute->bufflen; i++) {
                brute->buff[i] = 0;
                brute->tp[i] = brute->table;
            }
            break;
        }
        for(p = brute->table; *p; p++) {
            if(*p == chr) {
                brute->tp[i] = p + 1;
                break;
            }
        }
    }
    if(brute->tp[0] != brute->table) brute->tp[0]--;
}



void mybrute_free(mybrute_t *brute) {
    free(brute->buff);
    free(brute->tp);
    free(brute);
}


