/*
    Copyright 2006,2007,2008,2009 Luigi Auriemma

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

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "mybrute.h"

#ifdef WIN32
    #include <winsock.h>
    #include "winerr.h"

    #define close   closesocket
    #define sleep   Sleep
    #define usleep  sleep
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <pthread.h>

    #define stristr     strcasestr
    #define stricmp     strcasecmp
    #define strnicmp    strncasecmp
#endif

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;



#ifdef WIN32
    #define quick_thread(NAME, ARG) DWORD WINAPI NAME(ARG)
    #define thread_id   DWORD
#else
    #define quick_thread(NAME, ARG) void *NAME(ARG)
    #define thread_id   pthread_t
#endif

thread_id quick_threadx(void *func, void *data) {
    thread_id       tid;
#ifdef WIN32
    if(!CreateThread(NULL, 0, func, data, 0, &tid)) return(0);
#else
    pthread_attr_t  attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(pthread_create(&tid, &attr, func, data)) return(0);
#endif
    return(tid);
}



#define VER             "0.2.3d"
#define BUFFSZ          16384       // sys_packetReceived[MAX_MSGLEN]

#define SENDTO(x,y)     if(sendto(sd, x, y, 0, (struct sockaddr *)&peer, sizeof(peer))  \
                          < 0) std_err();

#define RECVFROM(x,y)   len = recvfrom(sd, x, y, 0, NULL, NULL);                        \
                        if(len < 0) len = 0;    /* std_err(); */                        \
                        x[len] = 0;

#define FLOODPROT       500
                        //  // TTimo - https://zerowing.idsoftware.com/bugzilla/show_bug.cgi?id=534
                        //  time = Com_Milliseconds();
                        //  if (time<(lasttime+500)) {
                        //      return;
                        //  }
                        //  lasttime = time;



u8 *firstline(u8 *fname);
u8 *show_gamez_list(void);
void init_gamez(void);
void pwdguess_help(void);
void rcon_cmd_help(void);
void rcon_host(u8 *host, u16 *port);
u8 *get_pass(u8 *buff);
void rcon_info(int sd, u8 *buff);
void get_chall_rcon(int sd, u8 *buff);
void textf_send(int sd, u8 *buff, u8 *pass, u8 *fname);
void showinfo(u8 *data, int len);
int checkifrcon(int sd, u8 *buff);
quick_thread(rcon_trecv, int sd);
quick_thread(brute_trecv, int sd);
int rcon_build(u8 *buff, u8 *pass, u8 *cmd);
void rconbrute(int sd, u8 *buff, u8 *pass);
void rcon(int sd, u8 *buff, u8 *pass, u8 *cmd);
int mycpy(u8 *dst, u8 *src);
void delimit(u8 *data);
void mysend(int sd, u8 *in, int insz);
void myrecv(int sd, u8 *out, int outsz);
u8 *str_reply(u8 *buff);
int timeout(int sock);
u32 resolv(char *host);
void std_err(void);



enum {
    QUAKE3,
    MOH,
    HALFLIFE,
    DOOM3,
    QUAKE2,
    IGI2,

        // add others here and in init_gamez()

    TYPE_LIMIT  // delimiter
};



typedef struct {
    u8      *name;          // name of the engine or game
    u8      *info;          // the query for retrieving server's informations
    int     info_size;      // size of the above query
    u8      *brute_cmd;     // a valid rcon command to use during brute forcing
    int     nt;             // info: 1 or 0 
    int     chr;            // info: char delimiter
    int     front;          // info: skip bytes at the beginning
    int     rear;           // info: skip bytes at the end
    u8      *rcon_str;      // the rcon format string
    int     rcon_off;       // the offset from which starts the rcon data (\xff skip)
    int     rcon_str_type;  // for building different rcon commands
    int     rcon_str_pars;  // parameters, 2 (pass + cmd) or 3 (chall + pass + cmd)
    u8      *rcon_chall;    // does it requires a challenge?
} gamez_t;



gamez_t gamez[TYPE_LIMIT];
struct  sockaddr_in peer;
int     timesecs   = 1,
        bfound,
        rcon_type  = -1,
        rcon_chall = 0,
        rconsync   = 1,
        nolimits   = 0;
u8      *bpwd      = NULL;



int main(int argc, char *argv[]) {
    mybrute_t   *brutex = NULL;
    FILE    *fd;
    int     sd,
            i,
            info   = 0,
            brute  = 0,
            bdelay = FLOODPROT,
            bwopt  = 0;
    u16     port;
    u8      *buff  = NULL,  // this is the buffer for almost everything
            *line  = NULL,  // input buffer
            *pass  = NULL,
            *cmd   = NULL,
            *bt    = NULL,
            *bw    = NULL,
            *br    = NULL,
            *textf = NULL,
            *p;

#ifdef WIN32
    WSADATA    wsadata;
    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif

    //setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    fputs("\n"
        "Multi engine RCON tool and password guesser "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stderr);

    init_gamez();   // call it now!

    if(argc < 3) {
        fprintf(stderr, "\n"
            "Usage: %s [options] <host> <port>\n"
            "\n"
            "Options:\n"
            "-p PASS  specify the password, by default it is requested at runtime\n"
            "-P FILE  takes the password from the first line of FILE\n"
            "-c CMD   sends the command CMD, shows the reply and exits\n"
            "-i       requests server informations before starting\n"
            "-I       as above but exits after having received the informations\n"
            "-f FILE  sends all the commands included in the file FILE, line per line\n"
            "-t TYPE  select the type of rcon, the following TYPEs are supported:%s\n"
            "         type 0 is the default. type is automatically retrieved if you\n"
            "         use the -i option which will scan all the available query types\n"
            "-a       asynchronous commands, the tool waits all the server's data before\n"
            "         allowing to insert new commands, ever disabled with -c and -f\n"
            "-s SEC   seconds for timeout in the default synchronous mode (%d)\n"
            "-b ?     shows the password guessing options\n"
            "         For testing the RCON Denial of Service try the following:\n"
            "           multircon -x -i -b 10 09AZaz -d 100 SERVER PORT\n"
            "\n",
            argv[0], show_gamez_list(), timesecs
        );
        exit(1);
    }

    if(!strcmp(argv[argc - 1], "?")) {
        pwdguess_help();
    }

    argc -= 2;
    for(i = 1; i < argc; i++) {
        switch(argv[i][1]) {
            case 'p': pass      = strdup(argv[++i]);    break;
            case 'P': pass      = firstline(argv[++i]); break;
            case 'c': cmd       = argv[++i];            break;
            case 'i': info      = 1;                    break;
            case 'I': info      = 2;                    break;
            case 'f': textf     = argv[++i];            break;
            case 't': {
                rcon_type = atoi(argv[++i]);
                if(rcon_type >= TYPE_LIMIT) rcon_type = -1;
                } break;
            case 'a': rconsync  = 0;                    break;
            case 's': timesecs  = atoi(argv[++i]);      break;
            case 'b': {
                if(!strcmp(argv[i + 1], "?")) pwdguess_help();
                brute           = atoi(argv[++i]);
                bt              = argv[++i];
                } break;
            case 'B': br        = argv[++i];            break;
            case 'w': {
                brute           = -1;
                bw              = argv[++i];
                } break;
            case 'W': bwopt     = atoi(argv[++i]);      break;
            case 'd': bdelay    = atoi(argv[++i]);      break;
            case 'x': nolimits  = 1;                    break;
            default: {
                    fprintf(stderr, "\nError: wrong command-line argument (%s)\n\n", argv[i]);
                    exit(1);
                } break;
        }
    }

    port = atoi(argv[argc + 1]);
    rcon_host(argv[argc], &port);

    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sd < 0) std_err();

    buff = malloc(BUFFSZ + 1);  // + 1 avoid any problem
    if(!buff) std_err();

    if(info) {
        rcon_info(sd, buff);
    }

    if(rcon_type < 0) {
        rcon_type = QUAKE3;
    }
    fprintf(stderr, "- rcon type %d \"%s\"\n", rcon_type, gamez[rcon_type].name);
    if(info == 2) goto quit;

    if(gamez[rcon_type].rcon_chall) {
        get_chall_rcon(sd, buff);
    }

    if(rcon_type == IGI2) rconsync = 0;

    if(brute) {
        if(!nolimits) {
            fprintf(stderr, "- check if rcon is active\n");
            if(checkifrcon(sd, buff) < 0) {
                fprintf(stderr, "Error: the rcon service is not active on the server\n\n");
                exit(1);
            }
        }

#ifndef WIN32
        bdelay *= 1000;
#endif

        bfound = 0;
        SENDTO("", 0);  // required!
        if(!nolimits) {
            if(!quick_threadx(brute_trecv, (void *)sd)) {
                fprintf(stderr, "\nError: unable to create thread\n");
                exit(1);
            }
        }

        printf("- password guessing with command \"%s\"\n",
            gamez[rcon_type].brute_cmd ? gamez[rcon_type].brute_cmd : (u8 *)"");

        if(brute > 0) {
            printf("- start brute forcing (%d - \"%s\")\n", brute, bt);
            brutex = mybrute_init(brute, bt);
            if(!brutex) {
                fprintf(stderr, "\nError: mybrute initialization error\n");
                exit(1);
            }
            bpwd = brutex->buff;
            if(br) {
                strncpy(bpwd, br, brute);
                mybrute_restore(brutex);
            }
            while(mybrute(brutex, 0) && !bfound) {
                rconbrute(sd, buff, bpwd);
                printf("%s\r", bpwd);
                usleep(bdelay);
            }

        } else if(brute < 0) {
            printf("- init wordlist \"%s\"\n", bw);
            brutex = mybrute_init(64, "");
            if(!brutex) {
                fprintf(stderr, "\nError: mybrute initialization error\n");
                exit(1);
            }
            bpwd = brutex->buff;
            if(!strcmp(bw, "-")) {
                fd = stdin;
            } else {
                fd = fopen(bw, "rb");
                if(!fd) std_err();
            }
            if(bwopt) {
                switch(bwopt) {
                    case 1: bwopt = MYBRUTE_WORD_AUTOCASE;  break;
                    case 2: bwopt = MYBRUTE_WORD_LOWER;     break;
                    case 3: bwopt = MYBRUTE_WORD_UPPER;     break;
                    default: {
                        fprintf(stderr, "\nError: you have specified a wrong wordlist option number (%d)\n\n", bwopt);
                        exit(1);
                        } break;
                }
                mybrute_options(brutex, bwopt);
            }
            while(mybrute_word(brutex, fd) && !bfound) {
                rconbrute(sd, buff, bpwd);
                printf("%-79s\r", bpwd);
                usleep(bdelay);
            }
            if(fd != stdin) fclose(fd);
        }

        if(brutex) mybrute_free(brutex);
        if(!bfound) {
            printf("\n- password not found\n");
        }
        goto quit;
    }

    if(!pass) {
        pass = get_pass(buff);
    }

    if(cmd) {
        rconsync = 1;
        rcon(sd, buff, pass, cmd);
        goto quit;
    }

    if(textf) {
        rconsync = 1;
        textf_send(sd, buff, pass, textf);
        goto quit;
    }

    line = malloc(BUFFSZ + 1);
    if(!line) std_err();
    fprintf(stderr, "- the following are the commands handled internally by this tool:\n");
    rcon_cmd_help();

    if(!rconsync) {
        SENDTO("", 0);  // required!
        if(quick_threadx(rcon_trecv, (void *)sd)) {
            fprintf(stderr, "\nError: unable to create thread\n");
            exit(1);
        }
    }

    for(;;) {
        if(rconsync) printf("\n: ");
        //fflush(stdin);
        if(!fgets(line, BUFFSZ, stdin)) break;
        delimit(line);

        p = strchr(line, ' ');          // multircon's commands and values
        if(p) *p = 0;

        if(!stricmp(line, "/rcon_pass")) {
            free(pass);
            if(p) {
                pass = strdup(p + 1);
            } else {
                pass = get_pass(line);
            }
            continue;
        }

        if(!stricmp(line, "/rcon_host") && p) {
            rcon_host(p + 1, &port);
            continue;
        }

        if(!stricmp(line, "/rcon_port") && p) {
            port = atoi(p + 1);
            rcon_host(NULL, &port);
            continue;
        }

        if(!stricmp(line, "/rcon_type")) {
            if(!p) {
                printf(
                    "%s\n"
                    "- current is %d \"%s\"\n",
                    show_gamez_list(), rcon_type, gamez[rcon_type].name);
            } else if(p[1] == '?') {
                printf("%s\n", show_gamez_list());
            } else {
                rcon_type = atoi(p + 1);
                if((rcon_type < 0) || (rcon_type >= TYPE_LIMIT)) {
                    fprintf(stderr, "- invalid rcon type\n");
                    rcon_type = QUAKE3;
                }
                printf("- rcon type %d \"%s\"\n", rcon_type, gamez[rcon_type].name);
            }
            continue;
        }

        if(!stricmp(line, "/rcon_chall") && gamez[rcon_type].rcon_chall) {
            get_chall_rcon(sd, buff);
            continue;
        }

        if(!stricmp(line, "/rcon_help")) {
            rcon_cmd_help();
            continue;
        }

        if(!stricmp(line, "/rcon_info")) {
            rcon_info(sd, buff);
            continue;
        }

        if(p) *p = ' ';                 // in case *p was nulled

        rcon(sd, buff, pass, line);
    }

quit:
    close(sd);
    if(buff) free(buff);
    if(line) free(line);
    if(pass) free(pass);
    return(0);
}



u8 *firstline(u8 *fname) {
    FILE    *fd;
    u8      *line;

    fd = fopen(fname, "rb");
    if(!fd) std_err();
    line = malloc(256);
    line[0] = 0;
    while(fgets(line, 256, fd)) {
        delimit(line);
        if(line[0]) break;
    }
    fclose(fd);
    return(line);
}



u8 *show_gamez_list(void) {
    int     i,
            len;
    static u8   buff[256];  // enough

    len = 0;
    for(i = 0; i < TYPE_LIMIT; i++) {
        if(!(i % 3)) len += sprintf(buff + len, "\n         ");
        len += sprintf(buff + len, "%d = %-16s ", i, gamez[i].name);
    }
    return(buff);
}



void init_gamez(void) {
    memset(&gamez, 0, sizeof(gamez));                   // useless, in case we forgot something

    gamez[QUAKE3].name            = "Quake 3 engine";
    gamez[QUAKE3].info            = "\xff\xff\xff\xff" "getinfo xxx\n";
    gamez[QUAKE3].info_size       = 16;
    gamez[QUAKE3].brute_cmd       = "cvarlist rcon";    // rconPassword
    gamez[QUAKE3].nt              = 1;
    gamez[QUAKE3].chr             = '\\';
    gamez[QUAKE3].front           = 4;
    gamez[QUAKE3].rear            = 0;
    gamez[QUAKE3].rcon_str        = "\xff\xff\xff\xff" "rcon %s %s";
    gamez[QUAKE3].rcon_off        = 4;
    gamez[QUAKE3].rcon_str_type   = 0;                  // no binary
    gamez[QUAKE3].rcon_str_pars   = 2;                  // pass and cmd
    gamez[QUAKE3].rcon_chall      = NULL;

    gamez[MOH].name               = "Medal of Honor";
    gamez[MOH].info               = "\xff\xff\xff\xff" "\x02" "getinfo xxx\n";
    gamez[MOH].info_size          = 17;
    gamez[MOH].brute_cmd          = "cvarlist rcon";
    gamez[MOH].nt                 = 1;
    gamez[MOH].chr                = '\\';
    gamez[MOH].front              = 5;
    gamez[MOH].rear               = 0;
    gamez[MOH].rcon_str           = "\xff\xff\xff\xff" "\x02" "rcon %s %s";
    gamez[MOH].rcon_off           = 5;
    gamez[MOH].rcon_str_type      = 0;
    gamez[MOH].rcon_str_pars      = 2;
    gamez[MOH].rcon_chall         = NULL;

    gamez[HALFLIFE].name          = "Half-Life";
    gamez[HALFLIFE].info          = "\xff\xff\xff\xff" "infostring\n\0";
    gamez[HALFLIFE].info_size     = 16;
    gamez[HALFLIFE].brute_cmd     = "rcon_password";    // "cvarlist rcon";
    gamez[HALFLIFE].nt            = 1;
    gamez[HALFLIFE].chr           = '\\';
    gamez[HALFLIFE].front         = 23;
    gamez[HALFLIFE].rear          = 0;
    gamez[HALFLIFE].rcon_str      = "\xff\xff\xff\xff" "rcon %i %s %s";
    gamez[HALFLIFE].rcon_off      = 5;
    gamez[HALFLIFE].rcon_str_type = 0;
    gamez[HALFLIFE].rcon_str_pars = 3;
    gamez[HALFLIFE].rcon_chall    = "\xff\xff\xff\xff" "challenge rcon\n";

    gamez[DOOM3].name             = "Doom 3 engine";
    gamez[DOOM3].info             = "\xff\xff" "getInfo\0" "\0\0\0\0";
    gamez[DOOM3].info_size        = 14;
    gamez[DOOM3].brute_cmd        = "listCvars net_serverRemoteConsolePassword";
    gamez[DOOM3].nt               = 0;
    gamez[DOOM3].chr              = '\0';
    gamez[DOOM3].front            = 23;
    gamez[DOOM3].rear             = 8;
    gamez[DOOM3].rcon_str         = "\xff\xff" "rcon";
    gamez[DOOM3].rcon_off         = 2;
    gamez[DOOM3].rcon_str_type    = 1;
    gamez[DOOM3].rcon_str_pars    = 2;
    gamez[DOOM3].rcon_chall       = NULL;

    gamez[QUAKE2].name            = "Quake 2 engine";
    gamez[QUAKE2].info            = "\xff\xff\xff\xff" "status";
    gamez[QUAKE2].info_size       = 10;
    gamez[QUAKE2].brute_cmd       = "rcon_password";    // "cvarlist rcon";
    gamez[QUAKE2].nt              = 1;
    gamez[QUAKE2].chr             = '\\';
    gamez[QUAKE2].front           = 4;
    gamez[QUAKE2].rear            = 0;
    gamez[QUAKE2].rcon_str        = "\xff\xff\xff\xff" "rcon %s %s";
    gamez[QUAKE2].rcon_off        = 4;
    gamez[QUAKE2].rcon_str_type   = 0;
    gamez[QUAKE2].rcon_str_pars   = 2;
    gamez[QUAKE2].rcon_chall      = NULL;

    gamez[IGI2].name              = "Project IGI 2";
    gamez[IGI2].info              = "\\status\\";
    gamez[IGI2].info_size         = 8;
    gamez[IGI2].brute_cmd         = NULL;
    gamez[IGI2].nt                = 1;
    gamez[IGI2].chr               = '\\';
    gamez[IGI2].front             = 0;
    gamez[IGI2].rear              = 0;
    gamez[IGI2].rcon_str          = "/%s";
    gamez[IGI2].rcon_off          = 24;
    gamez[IGI2].rcon_str_type     = 0;
    gamez[IGI2].rcon_str_pars     = 1;
    gamez[IGI2].rcon_chall        = "/";
}



void pwdguess_help(void) {
    fprintf(stderr, "\n"
        "Password guessing:\n"
        "-b L T   enable password guessing through brute forcing\n"
        "         L is the max length of the password while T is the table to use\n"
        "         you must specify the first and last chars of the table, for example\n"
        "         az for chars from a to z while azAZ09 for any alphanumeric char\n"
        "-B OLD   restores a brute forcing from the word OLD (-b required)\n"
        "-w FILE  enable password guessing through wordlist in the file FILE\n"
        "-W OPT   wordlist options, use OPT equal to 1 for activating the auto case\n"
        "         scanning which tries all the possible case combinations (ab, Ab, AB),\n"
        "         2 for forcing the lower case (ab) or 3 for the upper case (AB)\n"
        "-d MS    milliseconds used as delay in the password guessing (%d), if you use\n"
        "         a very small number you can flood the server which will no longer\n"
        "         accept the remote admin's commands due to the Q3 flood protection\n"
        "-x       continue the scanning also if the password is found (compatibilty)\n"
        "\n"
        "Note: some servers use automatic IP banning to avoid brute forcing!\n"
        "\n", FLOODPROT);
    exit(1);
}



void rcon_cmd_help(void) {
    printf(
        "  /rcon_help               this help\n"
        "  /rcon_pass [PASS]        for re-inserting the password\n"
        "  /rcon_host HOST[:PORT]   for changing server and password\n"
        "  /rcon_port PORT          for changing only the server's port\n"
        "  /rcon_type [NUM]         for changing the type of rcon, use ? for list\n"
        "  /rcon_info               query the server\n"
    );
    if(gamez[rcon_type].rcon_chall) {
        printf("  /rcon_chall              for getting a new rcon challenge\n");
    }
}



void rcon_host(u8 *host, u16 *port) {
    u8      *p;

    if(host) {
        p = strchr(host, ':');
        if(p) {
            *p = 0;
            *port = atoi(p + 1);
        }
        peer.sin_addr.s_addr = resolv(host);
    }
    peer.sin_port        = htons(*port);
    peer.sin_family      = AF_INET;

    printf("- target   %s : %hu\n",
        inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
}



u8 *get_pass(u8 *buff) {
    u8      *pass;

    fprintf(stderr, "- insert password: ");
    //fflush(stdin);
    fgets(buff, BUFFSZ, stdin);
    delimit(buff);
    pass = strdup(buff);
    return(pass);
}



void rcon_info(int sd, u8 *buff) {
    int     i,
            len;

    if(rcon_type < 0) {
        fprintf(stderr, "- query scanning:\n");
        for(i = 0; i < TYPE_LIMIT; i++) {
            printf("- try \"%s\" query\n", gamez[i].name);
            SENDTO(gamez[i].info, gamez[i].info_size);
            if(!timeout(sd)) break;
        }
        if(i == TYPE_LIMIT) {
            fprintf(stderr, "\nError: no reply received, probably the server is offline\n\n");
            exit(1);
        }
        rcon_type = i;
    } else {
        mysend(sd, gamez[rcon_type].info, gamez[rcon_type].info_size);
    }

    RECVFROM(buff, BUFFSZ);
    showinfo(buff, len);
}



void get_chall_rcon(int sd, u8 *buff) {
    int     len;
    u8      *p;

        /* EXPERIMENTAL since it's actually ONLY for Half-Life (NOT Source) */

    fprintf(stderr, "- send challenge request\n");
    mysend(sd, gamez[rcon_type].rcon_chall, strlen(gamez[rcon_type].rcon_chall));
    RECVFROM(buff, BUFFSZ);
    p = strrchr(buff + gamez[rcon_type].rcon_off, ' ');
    if(!p) {
        fprintf(stderr, "\nError: no challenge found: %s\n\n", buff);
        exit(1);
    }
    sscanf(p + 1, "%u", &rcon_chall);
    fprintf(stderr, "- use rcon challenge %i\n", rcon_chall);
}



void textf_send(int sd, u8 *buff, u8 *pass, u8 *fname) {
    FILE    *fd;
    u8      *line;

    if(!strcmp(fname, "-")) {
        fd = stdin;
    } else {
        fd = fopen(fname, "rb");
        if(!fd) std_err();
    }

    line = malloc(BUFFSZ + 1);
    if(!line) std_err();

    while(fgets(line, BUFFSZ, fd)) {
        delimit(line);
        printf("  %s\n", line);
        rcon(sd, buff, pass, line);
    }

    if(fd != stdin) fclose(fd);
    free(line);
}



void showinfo(u8 *data, int len) {
    int     nt    = 0,
            front = 0,
            rear  = 0,
            chr   = 0;
    u8      *p,
            *limit;

    nt    = gamez[rcon_type].nt;
    chr   = gamez[rcon_type].chr;
    front = gamez[rcon_type].front;
    rear  = gamez[rcon_type].rear;

    limit  = data + len - rear;
    *limit = 0;
    data   += front;

    for(p = data; (data < limit) && p; data = p + 1, nt++) {
        p = strchr(data,  chr);
        if(p) *p = 0;

        if(nt & 1) {
            printf("%s\n", data);
        } else {
            if(!*data || !strcmp(data, "queryid") || !strcmp(data, "final")) break;
            printf("%30s: ", data);
        }
    }
}



int checkifrcon(int sd, u8 *buff) {
    u32     rnd;
    int     i,
            len;
    u8      pwd[8],
            *p;

    rnd = time(NULL);   // useless but is better to avoid a fixed password
    len = rnd % (sizeof(pwd) - 1);
    if(!len) len = 1;
    for(i = 0; i < len; i++) {
        pwd[i] = 'a' + (rnd % 24);
        rnd = (rnd * 0x343FD) + 0x269EC3;
        rnd >>= 3;  // sometimes useful
    }
    pwd[i] = 0;

    rconbrute(sd, buff, pwd);
    if(timeout(sd)) {
        fprintf(stderr, "\nError: no reply received, the server is offline or uses a different protocol\n\n");
        exit(1);
    }

    RECVFROM(buff, BUFFSZ);
    if(len <= 0) return(-1);
    p = str_reply(buff);
    printf("- reply from the server:\n  %s\n", p);
    if(stristr(p, "No rconpassword")) {
        bfound = -1;
        return(-1);
    }
    return(0);
}



quick_thread(rcon_trecv, int sd) {
    int     len;
    u8      *buff,
            *p;

    buff = malloc(BUFFSZ + 1);
    if(!buff) std_err();

    for(;;) {
        RECVFROM(buff, BUFFSZ);
        p = str_reply(buff);
        fputs(p, stdout);
    }

    free(buff);
}



quick_thread(brute_trecv, int sd) {
    int     len;
    u8      *buff,
            *p;

    buff = malloc(BUFFSZ + 1);
    if(!buff) std_err();

    for(;;) {
        RECVFROM(buff, BUFFSZ);
        p = str_reply(buff);
        if(stristr(p, "challenge")) {
            printf("\n- Seems to exist a problem with the rcon challenge:\n%s\n", p);
            if(gamez[rcon_type].rcon_chall) {
                fprintf(stderr, "- now I try to reget the rcon challenge\n");
                get_chall_rcon(sd, buff);
                continue;
            }
            bfound = 1;
            break;
        }
        if(stristr(p, "banned")) {
            printf("\n- Seems you have been banned:\n%s\n", p);
            bfound = 1;
            break;
        }
//        if(stristr(p, "cvars") || stristr(p, "cvarlist") || stristr(p, "v rcon_")) {
        if(p[0] == '\"') p++;
        if(
          p[0]                                      &&
          strnicmp(p, "disconnect", 10)             &&
          strnicmp(p, "bad rcon",   8)              &&
          strnicmp(p, "wrong rcon", 10)             &&
          strnicmp(p, "invalid password", 16)             &&
          strnicmp(p, "please enter password", 21)  &&
          strnicmp(p, "no rcon",    7)) {
            printf("\n\nPASSWORD FOUND!!! (%s)\n%s\n", bpwd, p);
            bfound = 1;
            break;
        }
    }

    free(buff);
    return(0);
}



int rcon_build(u8 *buff, u8 *pass, u8 *cmd) {
    int     len = 0;
    u8      *p;

    if(gamez[rcon_type].rcon_str_type) {
        p = buff;
        p += mycpy(p, gamez[rcon_type].rcon_str);
        if(gamez[rcon_type].rcon_str_pars > 2) {
            p += sprintf(p, "%i", rcon_chall);
        }
        p += mycpy(p, pass);
        p += mycpy(p, cmd);
        len = p - buff;
    } else {
        if(gamez[rcon_type].rcon_str_pars == 1) {
            len = sprintf(
                buff,
                gamez[rcon_type].rcon_str,
                cmd ? cmd : pass);
        } else if(gamez[rcon_type].rcon_str_pars == 2) {
            len = sprintf(
                buff,
                gamez[rcon_type].rcon_str,
                pass,
                cmd);
        } else {
            len = sprintf(
                buff,
                gamez[rcon_type].rcon_str,
                rcon_chall,
                pass,
                cmd);
        }
        len++;          // NULL byte included!
    }

/*  snprintf has been removed, bof protection is totally useless locally
    if((len < 0) || (len >= BUFFSZ)) {
        fprintf(stderr, "\nError: your RCON command is too long\n");
        exit(1);
    }
    len++;          // NULL byte included!
*/
    return(len);
}



void rconbrute(int sd, u8 *buff, u8 *pass) {
    int     len;

    len = rcon_build(buff, pass, gamez[rcon_type].brute_cmd);

    SENDTO(buff, len);
}



void rcon(int sd, u8 *buff, u8 *pass, u8 *cmd) {
    int     len;

    len = rcon_build(buff, pass, cmd);

    if(rconsync) {
        mysend(sd, buff, len);
        myrecv(sd, buff, BUFFSZ);
    } else {
        SENDTO(buff, len);
    }
}



int mycpy(u8 *dst, u8 *src) {
    u8      *p;

    for(p = dst; *src; src++, p++) {
        *p = *src;
    }
    *p++ = 0;   // NULL included
    return(p - dst);
}



void delimit(u8 *data) {
    while(*data && (*data != '\n') && (*data != '\r')) data++;
    *data = 0;
}



void mysend(int sd, u8 *in, int insz) {
    int     i;

    for(i = 3; i; i--) {
        SENDTO(in, insz);
        if(!timeout(sd)) break;
    }
    if(!i) {
        fprintf(stderr, "\nError: socket timeout, no reply received\n\n");
        exit(1);
    }
}



void myrecv(int sd, u8 *out, int outsz) {
    int     len;
    u8      *p;

    outsz -= 2; // added "\n"

    do {
        RECVFROM(out, outsz);
        p = str_reply(out);
        fputs(p, stdout);

    } while(!timeout(sd));
}



u8 *str_reply(u8 *buff) {
    u8      *base,
            *p,
            *l;

    base = buff + gamez[rcon_type].rcon_off;
    p    = base;

    if(rcon_type == DOOM3) {
        p += strlen(base) + 1;  // print
        p += 4;                 // 4 bytes

        if(!strnicmp(p, "#str_", 5)) {
            if(strstr(p, "4847")) {
                strcpy(p, "bad rcon password (#str_104847)\n");
            } else if(strstr(p, "4846")) {
                strcpy(p, "no rconpassword (#str_104846)\n");
            } else if(strstr(p, "4848")) {
                strcpy(p, "wrong command (#str_104848)\n");
            }
        }

    } else {
        p = strchr(base, '\n');
        if(p && (strnicmp(base, "print", p - base))) p = NULL;
        p = p ? (p + 1) : base;
    }

    l = p + strlen(p) - 1;
    if(*l > '\r') strcpy(l + 1, "\n");
    return(p);
}



int timeout(int sock) {
    struct  timeval tout;
    fd_set  fd_read;
    int     err;

    tout.tv_sec  = timesecs;
    tout.tv_usec = 0;
    FD_ZERO(&fd_read);
    FD_SET(sock, &fd_read);
    err = select(sock + 1, &fd_read, NULL, NULL, &tout);
    if(err < 0) std_err();
    if(!err) return(-1);
    return(0);
}



u32 resolv(char *host) {
    struct  hostent *hp;
    u32     host_ip;

    host_ip = inet_addr(host);
    if(host_ip == INADDR_NONE) {
        hp = gethostbyname(host);
        if(!hp) {
            fprintf(stderr, "\nError: Unable to resolv hostname (%s)\n", host);
            exit(1);
        } else host_ip = *(u32 *)hp->h_addr;
    }
    return(host_ip);
}



#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif


