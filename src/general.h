/* vim: set sw=4 sts=4 : */

/* Copyright (c) 2008, David B. Cortarello
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *   * Neither the name of Kwort nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
*/

#include "nqqueue.h"
#include "config.h"

#define MESSAGE_FILE "message.orig"

/* qmail-queue error codes */
#define EXIT_0     0			/* Success */
#define EXIT_11   11			/* address too long */
#define EXIT_400  71			/* temporary refusal to accept */
#define EXIT_500  31			/* permenent refusal to accept message SMTP: 5XX code */
#define EXIT_MSG  82			/* exit with custom error message */

#define BIG_BUFF  8192
#define SMALL_BUFF 4096
#define MINI_BUFF 1024

#define SECS(tv) (tv.tv_sec + tv.tv_usec / 1000000.0)

/* Debug flag */
int debug_flag;

/* Work directory */
char indexdir[PATH_MAX_NQQUEUE];

/* Times issue */
struct timeval start, stop;

/* From origin */
char MailFrom[ADDR_MAX_SIZE];

/* Destination emails */
PUStruct *RcptTo;

/* Number of total receivers */
int RcptTotal;

/* Number of local and remote receivers */
int LocalRcpt, RemoteRcpt;

/* Runned scanners data */
RSStruct *GlobalRunnedScanners;
int GlobalScanners;

/* Qmail queue's exit status */
int qstat;

void exit_clean(int error_code);
void copy(char *from, char *to);
int fd_move(int to, int from);
int fd_copy(int to, int from);
int IsLocal(const char *email);
int remove_files(char *dir);

