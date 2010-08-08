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

#define REJECTED_MESSAGE "Message rejected because it contains a virus"
#define PLUGIN_NAME "clamav"
#define PLUGIN_VERSION "1.0"

#define BUFF_SIZE 2048

char *plugin_name()
{
	return strdup(PLUGIN_NAME);
}

char *plugin_version()
{
	return strdup(PLUGIN_VERSION);
}

int is_clamav(char *clambuf, int *InHeaders)
{
	int i, j, k;
	int found;
	char *tmpstr;
	char *virus_name;
	int FoundVirus = 0;

	for (i = 0, j = 0; clambuf[i] != 0; ++i) {

		/* found a line */
		if (clambuf[i] == '\n' || clambuf[i] == '\r') {

			/* check for blank line, end of headers */
			for (k = j, found = 0; k < i; ++k) {

				switch (clambuf[k]) {

						/* skip blank spaces and new lines */
					case ' ':
					case '\n':
					case '\t':
					case '\r':
						break;

						/* found a non blank, so we are still in the headers */
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

			if ((tmpstr = strstr(&clambuf[j], "FOUND")) != NULL) {
				while (*tmpstr != ':' && tmpstr > clambuf)
					--tmpstr;
				++tmpstr;
				virus_name = strtok(tmpstr, " ");
				debug(2, "nqqueue: Virus found: %s\n", virus_name);
				return 1;
			}
			if (clambuf[i + 1] != 0)
				j = i + 1;
		}
	}
	return 0;
}

struct ModReturn *plugin_init(char *params, const char *mail, const char *From, const union Tos Rcpt, struct RSStruct *general, struct RSStruct *peruser)
{
	int pid, rmstat, n, fd;
	int pim[2];
	int InHeaders = 1, isclamav = 0;
	char *clamav_args[] = { "clamdscan", "--stdout", "-", NULL };
	struct ModReturn *ret = malloc(sizeof(struct ModReturn));
	char buffer[BUFF_SIZE];

	if ((fd = open(mail, O_RDONLY, 0644)) == -1) {
		debug(3, "nqqueue: error (%d) opening orig file %s in rw mode\n", errno, mail);
		return NULL;
	}

	debug(2, "nqqueue: Calling clamdscan\n");

	if (pipe(pim) != 0) {
		debug(3, "nqqueue: error (%d) generating pipes\n", errno);
		close(fd);
		return NULL;
    }

	/* fork clamdscan */
	switch (pid = vfork()) {
		case -1:
			debug(3, "nqqueue: error (%d) forking\n", errno);
			close(pim[0]);
			close(pim[1]);
			close(fd);
			return NULL;
		case 0:
			close(pim[0]);
			dup2(pim[1], 1);
			close(pim[1]);
			dup2(fd, 0);
			execve(CLAMAV_BINARY, clamav_args, 0);
			_exit(-1);
		default:
			close(pim[1]);
			/* Get the data and check what clamdscan told us */
			memset(buffer, 0, sizeof(buffer));
			while ((n = read(pim[0], buffer, BUFF_SIZE)) > 0) {
				if (InHeaders == 1)
					if(is_clamav(buffer, &InHeaders))
						isclamav = 1;
				memset(buffer, 0, n);
			}
			close(pim[0]);
	}

	close(fd);

	/* wait for clamdscan to finish */
	if (waitpid(pid, &rmstat, 0) == -1) {
		debug(3, "nqqueue: error (%d) waiting for clamdscan to end\n", errno);
		return NULL;
	}

	/* check if the child died on a signal */
	if (WIFSIGNALED(rmstat)) {
		debug(3, "nqqueue: error (%d) clamdscan received a signal and died\n", errno);
		return NULL;
	}

	/* If clamdscan return something not 0 or 1, then it was an error */
	n = WEXITSTATUS(rmstat);
	if (n != 0 && n != 1) {
		debug(3, "nqqueue: error (%d) clamdscan endded with error: %d\n", errno, WEXITSTATUS(rmstat));
		return NULL;
	}

	/* Final issues: Point file to the new file and set to reject or not */
	ret->NewFile = NULL;
    ret->ret = isclamav;
	if (params != NULL && !strcmp(params, "pass")) {
		ret->rejected = 0;
		ret->message = NULL;
	}
	else {
		ret->rejected = isclamav;
		if (isclamav)
			ret->message = strdup(REJECTED_MESSAGE);
		else
			ret->message = NULL;
	}
	return ret;
}
