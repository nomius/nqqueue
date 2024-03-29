
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <nqqueue.h>
#include <config.h>

/*
 * If you want a global user, replace Rcpt.rcpt by your global user using
 * quotes like: "vpopmail" or "dspam"
 */
#define GLOBAL_USER Rcpt.rcpt

#define PLUGIN_NAME "spamassassin"
#define PLUGIN_VERSION "1.0b"
#define REJECTED_MESSAGE "Message rejected because it was considered spam"

#define BUFF_SIZE 2048

char *plugin_name()
{
	return strdup(PLUGIN_NAME);
}

char *plugin_version()
{
	return strdup(PLUGIN_VERSION);
}

int is_spamassassin(char *spambuf, int *InHeaders)
{
	int i, j, k;
	int found;

	for (i = 0, j = 0; spambuf[i] != 0; ++i) {
		/* found a line */
		if (spambuf[i] == '\n' || spambuf[i] == '\r') {
			/* check for blank line, end of headers */
			for (k = j, found = 0; k < i; ++k) {
				switch (spambuf[k]) {
						/* skip blank spaces and new lines */
					case ' ':
					case '\n':
					case '\t':
					case '\r':
						break;
						/* found a non blank, so we are still in the
						 * headers */
					default:
						/* set the found non blank char flag */
						found = 1;
						break;
				}
			}
			if (found == 0) {
				*InHeaders = 0;
				return 0;
			}

			if (strncmp(spambuf + j, "X-Spam-Flag: YES", 16) == 0) {
				*InHeaders = 1;
				return 1;
			}

			if (spambuf[i + 1] != 0)
				j = i + 1;
		}
	}
	return 0;
}

ModReturn *plugin_init(char *params, char *mail, const char *From, const Destinations Rcpt, RSStruct *general, RSStruct *peruser)
{
	int pid, rmstat, n, fd, orig_fd;
	int pim[2];
	int InHeaders = 1;
	int isspamassassin = 0;
	char *spamc_args[] = { "spamc", "-u", GLOBAL_USER, NULL };
	char new_mesg[PATH_MAX_NQQUEUE];
	ModReturn *ret = malloc(sizeof(ModReturn));
	char buffer[BUFF_SIZE];

	NewNameRename(mail, new_mesg);

	if ((orig_fd = open(mail, O_RDONLY, 0644)) == -1) {
		debug(3, "nqqueue: error (%d) opening orig file %s in rw mode\n", errno, mail);
		return NULL;
	}

	debug(2, "nqqueue: Calling spamc\n");

	if (pipe(pim) != 0) {
		debug(3, "nqqueue: error (%d) generating pipes\n", errno);
		close(orig_fd);
		return NULL;
	}

	/* fork dspam */
	switch (pid = vfork()) {
		case -1:
			debug(3, "nqqueue: error (%d) forking\n", errno);
			close(pim[0]);
			close(pim[1]);
			close(orig_fd);
			return NULL;
		case 0:
			close(pim[0]);
			dup2(pim[1], 1);
			close(pim[1]);
			dup2(orig_fd, 0);
			execve(SPAMC_BINARY, spamc_args, 0);
			_exit(-1);
		default:
			close(pim[1]);
			/* Open dst message file */
			if ((fd = open(new_mesg, O_RDWR | O_CREAT | O_TRUNC, 0644)) == -1) {
				debug(3, "nqqueue: error (%d) opening dst file %s in rw mode\n", errno, new_mesg);
				return NULL;
			}
			/* Get the data and check what dspam told us */
			memset(buffer, 0, sizeof(buffer));
			while ((n = read(pim[0], buffer, BUFF_SIZE)) > 0) {
				if (InHeaders == 1)
					if (is_spamassassin(buffer, &InHeaders))
						isspamassassin = 1;
				write(fd, buffer, n);
				memset(buffer, 0, sizeof(buffer));
			}
			close(orig_fd);
			close(fd);
	}

	/* wait for dspam to finish */
	if (waitpid(pid, &rmstat, 0) == -1) {
		debug(3, "nqqueue: error (%d) waiting for dspam to end\n", errno);
		unlink(new_mesg);
		return NULL;
	}

	/* check if the child died on a signal */
	if (WIFSIGNALED(rmstat)) {
		debug(3, "nqqueue: error (%d) dspam received a signal and died\n", errno);
		unlink(new_mesg);
		return NULL;
	}

	/* If dspam return something not 0, then it's an error */
	if (WEXITSTATUS(rmstat) != 0) {
		debug(3, "nqqueue: error (%d) dspam endded with error: %d\n", errno, WEXITSTATUS(rmstat));
		unlink(new_mesg);
		return NULL;
	}

	/* Final issues: Point file to the new file and set to reject or not */
	unlink(mail);
   	if (!(ret= malloc(sizeof(ModReturn))))
		return NULL;

	ret->NewFile = strdup(new_mesg);
	ret->ret = isspamassassin;
	if (params != NULL && !strcmp(params, "pass")) {
		ret->rejected = 0;
		ret->message = NULL;
	}
	else {
		ret->rejected = isspamassassin;
		ret->message = isspamassassin ? strdup(REJECTED_MESSAGE) : NULL;
	}
	return ret;
}
