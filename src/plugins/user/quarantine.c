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
#include <time.h>
#include <nqqueue.h>
#include <config.h>

#if HAVE_VPOPMAIL
#define VQUAD "vquad"
#endif

#define REJECTED_GENERAL_MESSAGE "Message putted in vpopmail personal quarantine"
#define REJECTED_PERSONAL_MESSAGE "Message putted in vpopmail personal quarantine"
#define PLUGIN_NAME "quarantine"
#define PLUGIN_VERSION "1.0"

#define BUFF_SIZE 2048

#define STARTSWITH(x,y) (!strncmp(x, y, ((strlen(x))>(strlen(y))? (strlen(y)):(strlen(x)))))

char *plugin_name()
{
	return strdup(PLUGIN_NAME);
}

char *plugin_version()
{
	return strdup(PLUGIN_VERSION);
}

struct ModReturn *plugin_init(char *params, char *mail, const char *From, const union Tos Rcpt, struct RSStruct *general, struct RSStruct *peruser)
{
#if HAVE_VPOPMAIL
	char *vquad_args[5];
	struct stat st;
	char str_st_size[17];
#endif
	struct timeval date;
	struct RSStruct *init;
	struct ModReturn *ret = malloc(sizeof(struct ModReturn));
	int isdspam = 0, isclamav = 0, dspam_q = 0, clamav_q = 0, file_count;
	int orig_fd, dst_fd;
	int i, q = 0, pid, rmstat;
	char buffer[BUFF_SIZE];
	char *p;
	char *domain = strstr(Rcpt.rcpt, "@") + 1;
	char *user = strdup(Rcpt.rcpt);
	char *vdir = NULL;
	char *token, *subtoken;

	p = index(user, '@');
	*p = 0;

	/* Parsing params */
	for (i = 1, p = params;; i++, p = NULL) {
		token = strtok(p, ",");
		if (token == NULL)
			break;
		if (!strcmp(token, "clamav"))
			clamav_q = 1;
		else if (!strcmp(token, "dspam"))
			dspam_q = 1;
		else if (!strcmp(token, "all")) {
			clamav_q = 1;
			dspam_q = 1;
		}
		else if (STARTSWITH("q=", token)) {
			subtoken = index(token, '=');
			subtoken++;
			if (subtoken != NULL && !strcmp(subtoken, "global")) {
				q = 0;
			}
#if HAVE_VPOPMAIL
			else if (subtoken != NULL && STARTSWITH(subtoken, "vquad(")) {
				subtoken += 6;
				if (*subtoken == ')' || subtoken == NULL) {
					debug(2, "nqqueue: You must especify a quarantine directory in your VHOME\n");
					free(user);
					if (vdir)
						free(vdir);
				}
				else {
					q = 1;
					vdir = strdup(subtoken);
					/* Remove trailing ')' */
					vdir[strlen(vdir) - 1] = 0;
				}
			}
#endif
			else {
				debug(2, "nqqueue: No quarantine selected or can't push to the desired quarantine as it is not supported.\n");
				debug(2, "Supported quarantines: global");
#if HAVE_VPOPMAIL
				debug(2, " vquad(vdir)\n");
#else
				debug(2, " \n");
#endif
				free(user);
				if (vdir)
					free(vdir);
				return NULL;
			}
		}
		else
			debug(2, "nqqueue: Watch out dude, argument \"%s\" isn't supported\n", token);
	}

	/* Analize all general runned modules */
	init = general;
	while (init->plugin_name != NULL) {
		if (dspam_q && !strcmp(init->plugin_name, "dspam"))
			isdspam = init->returned;
		if (clamav_q && !strcmp(init->plugin_name, "clamav"))
			isclamav = init->returned;
		init++;
	}

	/* Analize all personal runned modules */
	init = peruser;
	while (init->plugin_name != NULL) {
		if (dspam_q && !strcmp(init->plugin_name, "dspam"))
			isdspam = init->returned;
		if (clamav_q && !strcmp(init->plugin_name, "clamav"))
			isclamav = init->returned;
		init++;
	}

	ret->message = NULL;
	if ((isdspam && dspam_q) || (isclamav && clamav_q)) {

		/* If we get here it's because we must put the message in quarantine */
		debug(2, "nqqueue: Putting message in quarantine\n");

		/* Open orig message file */
		if ((orig_fd = open(mail, O_RDONLY, 0644)) == -1) {
			debug(3, "nqqueue: error (%d) opening orig file %s in ro mode\n", errno, mail);
			free(user);
			free(ret);
			if (vdir)
				free(vdir);
			return NULL;
		}

		gettimeofday(&date, (struct timezone *)0);

		if (q == 0) {
			/* global quarantine */
			p = calloc(strlen(NQQUEUE_WORKDIR) + 4 + 11 + strlen(domain) + strlen(user) + 26, sizeof(char));
			sprintf(p, "%s/../quarantine/%s", NQQUEUE_WORKDIR, domain);
			mkdir(p, 0700);
			sprintf(p, "%s/%s", p, user);
			mkdir(p, 0700);
			/* Clear errors since user directory in quarantine might exist already */
			errno = 0;

			sprintf(p, "%s/%ld.%ld.%ld", p, date.tv_sec, date.tv_usec, (long int)getpid());

			/* Open dst message file */
			if ((dst_fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644)) == -1) {
				debug(3, "nqqueue: error (%d) opening dst file %s in rw mode\n", errno, p);
				free(user);
				free(ret);
				free(p);
				if (vdir)
					free(vdir);
				return NULL;
			}

			/* Now make the copy of the file in the quarantine */
			memset(buffer, 0, sizeof(buffer));
			while ((file_count = read(orig_fd, buffer, BUFF_SIZE)) > 0) {
				write(dst_fd, buffer, file_count);
				memset(buffer, 0, sizeof(buffer));
			}

			close(dst_fd);
			free(p);
			ret->message = strdup(REJECTED_GENERAL_MESSAGE);
		}
#if HAVE_VPOPMAIL
		else if (q == 1) {

			if (stat(mail, &st) == -1){
				free(user);
				free(ret);
				if (vdir)
					free(vdir);
				return NULL;
			}

			vquad_args[0] = VQUAD;
			vquad_args[1] = Rcpt.rcpt;
			vquad_args[2] = vdir;
			sprintf((char *)&str_st_size, "%d", st.st_size);
			vquad_args[3] = str_st_size;
			vquad_args[4] = NULL;

			debug(2, "nqqueue: Calling vquad\n");

			/* fork vquad */
			switch (pid = vfork()) {
				case -1:
					debug(3, "nqqueue: error (%d) forking\n", errno);
					close(orig_fd);
					free(user);
					free(ret);
					if (vdir)
						free(vdir);
					return NULL;
				case 0:
					dup2(orig_fd, 0);
					execve(VQUAD_BINARY, vquad_args, 0);
					_exit(-1);
			}

			/* wait for vquad to finish */
			if (waitpid(pid, &rmstat, 0) == -1) {
				debug(3, "nqqueue: error (%d) waiting for vquad to end\n", errno);
				close(orig_fd);
				free(user);
				free(ret);
				if (vdir)
					free(vdir);
				return NULL;
			}

			/* check if the child died on a signal */
			if (WIFSIGNALED(rmstat)) {
				debug(3, "nqqueue: error (%d) vquad received a signal and died\n", errno);
				close(orig_fd);
				free(user);
				free(ret);
				if (vdir)
					free(vdir);
				return NULL;
			}

			/* If vquad return something not 0, then it's an error */
			if (WEXITSTATUS(rmstat) != 0) {
				debug(3, "nqqueue: error (%d) vquad endded with error: %d\n", errno, WEXITSTATUS(rmstat));
				close(orig_fd);
				free(user);
				free(ret);
				if (vdir)
					free(vdir);
				return NULL;
			}

			ret->message = strdup(REJECTED_PERSONAL_MESSAGE);
		}
#endif
		close(orig_fd);
	}
	free(user);
	if (vdir)
		free(vdir);
	ret->NewFile = NULL;
	if (ret->message) {
		ret->ret = 1;
		ret->rejected = 1;
	}
	else {
		ret->ret = 0;
		ret->rejected = 0;
	}
	return ret;
}
