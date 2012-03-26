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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include "nqqueue.h"
#include "general.h"
#include "config.h"

/* Thread mutex used to avoid two calls of debug to write together */
pthread_mutex_t waiter = PTHREAD_MUTEX_INITIALIZER;

/* 
 * Cool debug function
 */
void debug(int level, char *fmt, ...)
{
	va_list ap;
	static char obuf[1024];
	int n = 0;

	if (debug_flag >= level) {
		va_start(ap, fmt);
		n = vsnprintf(obuf, sizeof obuf, fmt, ap);
		va_end(ap);
		while (pthread_mutex_lock(&waiter) != 0) ;
		write(fileno(stderr), obuf, n);
	}
	if (debug_flag > 4 && errno != 0) {
		fprintf(stderr, "nqqueue: '-> %s\n", strerror(errno));
		pthread_mutex_unlock(&waiter);
	}
	pthread_mutex_unlock(&waiter);
	errno = 0;
}

/* 
 * Clean up and exit
 */
void exit_clean(int error_code)
{
	debug(1, "nqqueue: exit with error code: %d\n", error_code);
	remove_files(indexdir);
	_exit(error_code);
}

/* 
 * Copy file from, to file to
 */
void copy(char *from, char *to)
{
	char buffer[BIG_BUFF];
	int fdfrom, fdto, red;

	fdfrom = open(from, O_RDONLY);
	fdto = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fdfrom == -1 || fdto == -1) {
		debug(0, "nqqueue: error (%d) copying file %s to %s, FdFrom: %d FdTo: %d\n", errno, from, to, fdfrom, fdto);
		exit_clean(EXIT_400);
	}
	while ((red = read(fdfrom, buffer, SMALL_BUFF)) > 0)
		write(fdto, buffer, red);
	close(fdfrom);
	close(fdto);
}

/* 
 * AllTrim function from Clipper
 */
char *alltrim(char *ptr)
{
	int i;

	while (*ptr == ' ' && ptr)
		ptr += 1;
	if (!ptr)
		return NULL;
	i = strlen(ptr) - 1;
	while (ptr[i] == ' ') {
		ptr[i] = '\0';
		i--;
	}
	if (ptr)
		return ptr;
	return NULL;
}

/* 
 * move a file descriptor
 */
int fd_move(int to, int from)
{
	if (to == from)
		return 0;
	if (fd_copy(to, from) == -1)
		return -1;
	close(from);
	return 0;
}

/* 
 * copy a file descriptor
 */
int fd_copy(int to, int from)
{
	if (to == from)
		return 0;
	if (fcntl(from, F_GETFL, 0) == -1)
		return -1;
	close(to);
	if (fcntl(from, F_DUPFD, to) == -1)
		return -1;
	return 0;
}

/* 
 * Returns 1 if is a local domain, otherwise, returns 0
 */
int IsLocal(const char *email)
{
	char *domain = NULL, buffer[MINI_BUFF];
	int ret = 0, ldomain = 0;
	FILE *rcpthosts = NULL;

	if(email == NULL || *email == '\0')
		return 0;
	if ((domain = index(email, '@')))
		domain += 1;
	else
		return 1;

	if (!(ldomain = strlen(domain)))
		return 0;

	snprintf(buffer, MINI_BUFF, "%s/rcpthosts", CONTROLDIR);
	if ((rcpthosts = fopen(buffer, "r")) == NULL) {
		debug(3, "nqqueue: error (%d) opening %s file\n", errno, buffer);
		exit_clean(EXIT_400);
	}
	while (fgets(buffer, MINI_BUFF, rcpthosts)) {
		if (!strncasecmp(domain, buffer, ldomain)) {
			ret = 1;
			break;
		}
	}
	fclose(rcpthosts);
	return ret;
}

/* 
 * From vpopmail source recursively remove a directory and all it's files
 */
int remove_files(char *dir)
{
	DIR *mydir;
	struct dirent *mydirent;
	struct stat statbuf;

	/* check the directory stat */
	if (lstat(dir, &statbuf) == 0) {

		/* if dir is not a directory unlink it */
		if (!S_ISDIR(statbuf.st_mode)) {
			if (unlink(dir) == 0)
				/* return success we deleted the file */
				return (0);
			else
				/* error, return error to calling function, we couldn't unlink the file */
				return (-1);
		}
	}
	else

		/* error, return error to calling function, * we couldn't lstat the file */
		return (-1);

	/* go to the directory, and check for error */
	if (chdir(dir) == -1) {

		/* error, return error to calling function */
		return (-1);
	}

	/* open the directory and check for an error */
	if ((mydir = opendir(".")) == NULL) {

		/* error, return error */
		return (-1);
	}

	while ((mydirent = readdir(mydir)) != NULL) {

		/* skip the current directory and the parent directory entries */
		if (strcmp(mydirent->d_name, ".") != 0 && strcmp(mydirent->d_name, "..") != 0) {

			/* stat the file to check it's type, I/O expensive */
			stat(mydirent->d_name, &statbuf);

			/* Is the entry a directory? */
			if (S_ISDIR(statbuf.st_mode)) {

				/* delete the sub tree, -1 means an error */
				if (remove_files(mydirent->d_name) == -1) {

					/* on error, close the directory stream */
					closedir(mydir);

					/* and return error */
					return (-1);
				}

				/* the entry is not a directory, unlink it to delete */
			}
			else {

				/* unlink the file and check for error */
				if (unlink(mydirent->d_name) == -1) {
					return (-1);
				}
			}
		}
	}

	/* close the directory stream, we don't need it anymore */
	closedir(mydir);

	/* go back to the parent directory and check for error */
	if (chdir("..") == -1) {
		return (-1);
	}

	/* delete the directory, I/O expensive */
	rmdir(dir);

	/* return success */
	return (0);
}

/* 
 * Returns the file name of a file used in a plugin:
 * If something+number is given, then something+(number+1) is returned.
 * Otherwise, something+0 is returned
 */
void NewNameRename(char *Init, char *Dest)
{
	int i, next = 0;

	if (Init == NULL || !*Init)
		return;

	for (i = strlen(Init) - 1; i > 0; i--)
		if (Init[i] == '+') {
			next = atoi(Init + i + 1);
			Init[i] = 0;
			break;
		}
	sprintf(Dest, "%s+%d", Init, next);
}

/*
 * Convert a string to lower
 */
void strlower(char *up, char *down){
	int i = 0;

	while (*(up+i)) {
		*(down+i) = tolower(*(up+i));
	   	i++;
	}
}

