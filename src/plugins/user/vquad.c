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
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#if HAVE_VPOPMAIL
#include <vauth.h>
#include <vpopmail_config.h>
#endif

#define BUFF_SIZE 84
#define BIG_BUFF_SIZE 2048

void check_hostname(char *s) {
	int i = 0;
	while (*(s+i)) {
		if (*(s+i) == '/') *(s+i) = 0x57;
		if (*(s+i) == ':') *(s+i) = 0x72;
		i++;
	}
}

char *filename(char *user, char *domain, char *directory, char *sizo)
{
	char right[BUFF_SIZE];
	char left[20];
	char middle[BUFF_SIZE];
	struct timeval tv;
	char *p = NULL;
	int i = 1;
#if HAVE_VPOPMAIL
	struct vqpasswd *vret;
	struct stat buf;
#endif
	long int timo = time(NULL);

	if (timo == -1)
		return NULL;

	/* Left */
	sprintf(left, "%ld", timo);

	/* Middle */
	middle[0] = 'M';
	if (gettimeofday(&tv, NULL) == -1)
		return NULL;
	i += sprintf(middle+1, "%ld", tv.tv_usec);
	middle[i++] = 'P';
	i += sprintf(middle+i, "%d", getpid());

#if HAVE_VPOPMAIL
	middle[i++] = 'V';
	if ((vret = vauth_getpw(user, domain)) == NULL)
		return NULL;

	p = calloc(strlen(vret->pw_dir) + 13 + strlen(directory) + 3, sizeof(char));

	if (vret->pw_dir == NULL)
		return NULL;

	sprintf(p, "%s/Maildir/%s/new", vret->pw_dir, directory);

	if (stat(p, &buf) == -1)
		return NULL;

	i += sprintf(middle+i, "%.16X", (unsigned int)buf.st_dev);
	middle[i++] = 'I';
	i += sprintf(middle+i, "%.16X_0", (unsigned int)buf.st_ino);

#endif

	/* Right */
	if (gethostname((char *)&right, BUFF_SIZE) == -1)
		return NULL;
	check_hostname((char *)&right);
	sprintf(right, "%s,S=%s", right, sizo);

	p = realloc(p, strlen(p)+strlen(left)+strlen(middle)+strlen(right));
	sprintf(p, "%s/%s.%s.%s", p, left, middle, right);

    return p;
}

int main(int argc, char *argv[])
{
	char *domain;
	char *user;
	char *p = NULL;
	char buffer[BIG_BUFF_SIZE];
	int fd, n;

	if (argv[1] == NULL || argv[2] == NULL || argv[3] == NULL) {
		fprintf(stderr, "vquad user@domain folder size\n");
		return 0;
	}

	domain = strchr(argv[1], '@');
	if (domain && domain + 1)
		domain++;

	user = strdup(argv[1]);

	p = index(user, '@');
	*p = 0;

#if HAVE_VPOPMAIL
	setuid(VPOPMAILUID);
	setgid(VPOPMAILGID);
#endif

	if ((p = filename(user, domain, argv[2], argv[3])) == NULL)
		return 1;

	umask(0022);
	if ((fd = open(p, O_WRONLY|O_CREAT|O_TRUNC, 0600)) == -1)
		return 1;
	memset(buffer, 0, BIG_BUFF_SIZE);

	while ((n = read(0, buffer, BIG_BUFF_SIZE)) > 0){
		write(fd, buffer, n);
		memset(buffer, 0, n);
	}
	close(fd);

	return 0;
}

