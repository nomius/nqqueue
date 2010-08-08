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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "nqqueue.h"
#include "general.h"
#include "cfg.h"

/* 
 * Delivery a mail to a local user to qmail-queue
 */
void delivery(char *To, char *File, struct RSStruct *local_runned_scanners, int PerUserScanners)
{
	int fd;
	int ret;
	int pid;
	int pim[2], pie[2];
	int qstat = 0;
	double utime;
	char buffer[SMALL_BUFF];

	/* re-open the file read only */
	if ((fd = open(File, O_RDONLY)) == -1) {
		debug(3, "nqqueue: error (%d) could not re-open message file: %s\n", errno, File);
		exit_clean(EXIT_400);
	}

	errno = 0;
	debug(2, "nqqueue: done, doing the local delivery to qmail-queue\n");

	if (pipe(pim) != 0)
		exit_clean(EXIT_400);

	if (pipe(pie) != 0)
		exit_clean(EXIT_400);

	/* fork qmail-queue */
	switch (pid = vfork()) {
		case -1:
			if (debug > 0)
				debug(3, "nqqueue: error (%d) forking qmail-queue\n", errno);
			close(pim[0]);
			close(pim[1]);
			close(pie[0]);
			close(pie[1]);
			_exit(EXIT_400);
		case 0:
			close(pim[1]);
			close(pie[1]);
			if (fd_move(0, pim[0]) == -1)
				_exit(120);
			if (fd_move(1, pie[0]) == -1)
				_exit(120);
			execl(QMAILQUEUE, "qmail-queue", 0);
			_exit(-1);
	}

	close(pim[0]);
	close(pie[0]);
	gettimeofday(&stop, (struct timezone *)0);

	/* print received line */
	utime = SECS(stop) - SECS(start);
	snprintf(buffer, sizeof(buffer), "Received: by nqqueue (%s) ppid: %d, pid: %d, time: %3.4f secs., scanners:\n", VERSION, getppid(), getpid(), utime);
	if (write(pim[1], buffer, strlen(buffer)) == -1) {
		debug(3, "nqqueue: error (%d) writing received line\n", errno);
		exit_clean(EXIT_400);
	}

	/* print each and every general scanner runned */
	for (ret = 0; GlobalRunnedScanners[ret].plugin_name != NULL; ret++) {
		snprintf(buffer, sizeof(buffer), "          %s (%s)\n", GlobalRunnedScanners[ret].plugin_name, GlobalRunnedScanners[ret].plugin_version);
		if (write(pim[1], buffer, strlen(buffer)) == -1) {
			debug(3, "nqqueue: error (%d) writing scanners\n", errno);
			exit_clean(EXIT_400);
		}
	}

	/* and now the per user scanner runned and free those too */
	for (ret = 0; local_runned_scanners[ret].plugin_name != NULL; ret++) {
		snprintf(buffer, sizeof(buffer), "          %s (%s)\n", local_runned_scanners[ret].plugin_name, local_runned_scanners[ret].plugin_version);
		if (write(pim[1], buffer, strlen(buffer)) == -1) {
			debug(3, "nqqueue: error (%d) writing scanners\n", errno);
			exit_clean(EXIT_400);
		}
		free(local_runned_scanners[ret].plugin_name);
		free(local_runned_scanners[ret].plugin_version);
	}
	if (local_runned_scanners)
		free(local_runned_scanners);

	/* write the message to qmail-queue */
	while ((ret = read(fd, buffer, sizeof(buffer))) > 0) {
		if (write(pim[1], buffer, ret) == -1) {
			debug(3, "nqqueue: error (%d) writing msg to qmail-queue\n", errno);
			exit_clean(EXIT_400);
		}
	}
	close(pim[1]);
	close(fd);

	sprintf(buffer, "F%s%cT%s%c%c", MailFrom, 0, To, 0, 0);
	if (write(pie[1], buffer, sizeof(buffer)) == -1)
		debug(3, "nqqueue: error (%d) writing addresses to qmail-queue\n", errno);
	close(pie[1]);

	free(To);

	/* Remove the File as we will not need it anymore */
	unlink(File);
	free(File);

	/* wait for qmail-queue to finish */
	if (waitpid(pid, &qstat, 0) == -1) {
		debug(3, "nqqueue: error (%d) forking qmail-queue\n", errno);
		exit_clean(EXIT_400);
	}

	/* hand the email to the qmail-queue */
	debug(2, "nqqueue: qmail-queue exited with exit value: %d\n", WEXITSTATUS(qstat));
}

/* 
 * Delivery a mail to a local user to qmail-queue
 */
void deliveryAll(char *File)
{
	int fd;
	int ret;
	int pid;
	int pim[2], pie[2];
	int qstat = 0;
	int count = 0;
	int count_old = 0;
	double utime;
	char buffer[SMALL_BUFF];

	/* re-open the file read only */
	if ((fd = open(File, O_RDONLY)) == -1) {
		debug(3, "nqqueue: error (%d) could not re-open message file: %s\n", errno, File);
		exit_clean(EXIT_400);
	}

	errno = 0;
	debug(2, "nqqueue: done, doing the remote delivery to qmail-queue\n");

	if (pipe(pim) != 0)
		exit_clean(EXIT_400);

	if (pipe(pie) != 0)
		exit_clean(EXIT_400);

	/* fork qmail-queue */
	switch (pid = vfork()) {
		case -1:
			if (debug > 0)
				debug(3, "nqqueue: error (%d) forking qmail-queue\n", errno);
			close(pim[0]);
			close(pim[1]);
			close(pie[0]);
			close(pie[1]);
			_exit(EXIT_400);
		case 0:
			close(pim[1]);
			close(pie[1]);
			if (fd_move(0, pim[0]) == -1)
				_exit(120);
			if (fd_move(1, pie[0]) == -1)
				_exit(120);
			execl(QMAILQUEUE, "qmail-queue", 0);
			_exit(-1);
	}

	close(pim[0]);
	close(pie[0]);
	gettimeofday(&stop, (struct timezone *)0);

	utime = SECS(stop) - SECS(start);
	snprintf(buffer, sizeof(buffer), "Received: by nqqueue (%s) ppid: %d, pid: %d, time: %3.4f s., scanners:\n", VERSION, getppid(), getpid(), utime);
	if (write(pim[1], buffer, strlen(buffer)) == -1) {
		debug(3, "nqqueue: error (%d) writing received line\n", errno);
		exit_clean(EXIT_400);
	}

	/* print each and every general scanner runned */
	for (ret = 0; GlobalRunnedScanners[ret].plugin_name != NULL; ret++) {
		snprintf(buffer, sizeof(buffer), "          %s (%s)\n", GlobalRunnedScanners[ret].plugin_name, GlobalRunnedScanners[ret].plugin_version);
		if (write(pim[1], buffer, strlen(buffer)) == -1) {
			debug(3, "nqqueue: error (%d) writing scanners\n", errno);
			exit_clean(EXIT_400);
		}
	}

	/* write the message to qmail-queue */
	while ((ret = read(fd, buffer, sizeof(buffer))) > 0) {
		if (write(pim[1], buffer, ret) == -1) {
			debug(3, "nqqueue: error (%d) writing msg to qmail-queue\n", errno);
			exit_clean(EXIT_400);
		}
		memset(buffer, 0, ret);
	}
	close(pim[1]);
	close(fd);

	/* Write the envelope information. */
	memset(buffer, 0, SMALL_BUFF);
	count = strlen(MailFrom) + 2;
	sprintf(buffer, "F%s%c", MailFrom, 0);
	write(pie[1], buffer, count);
	memset(buffer, 0, count);
	for (ret = 0; ret < RcptTotal; ret++) {
		if (RcptTo[ret].Index == (pthread_t)-1) {
			count = strlen(RcptTo[ret].To) + 2;
			sprintf(buffer, "T%s%c", RcptTo[ret].To, 0);
			write(pie[1], buffer, count);
			memset(buffer, 0, count);
			free(RcptTo[ret].To);
		}
	}
	sprintf(buffer, "%c", 0);
	write(pie[1], buffer, 1);
	close(pie[1]);

	/* wait for qmail-queue to finish */
	if (waitpid(pid, &qstat, 0) == -1) {
		debug(3, "nqqueue: error (%d) forking qmail-queue\n", errno);
		exit_clean(EXIT_400);
	}

	free(File);

	/* hand the email to the qmail-queue */
	debug(2, "nqqueue: qmail-queue exited with exit value: %d\n", WEXITSTATUS(qstat));
}

