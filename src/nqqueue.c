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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <pthread.h>
#include <dirent.h>
#include "general.h"
#include "delivery.h"
#include "nqqueue.h"
#include "cfg.h"

/* 
 * Load plugin symbols
 */
#define dynamic_symbol_resolution(ph, fn, sfn) \
	\
	/* Clear all dl errors before getting started */ \
	dlerror(); \
	\
	/* Use dlsym to resolve the given symbol and point fn function to the 
	 * resolved address [1] */ \
	*(void**)&fn = dlsym(ph, sfn); \
	\
	/* Check if there was any errors in dlsym() */ \
	if ((plerror = dlerror())) { \
		debug(4, "nqqueue: error, symbol %s in %s not found\n", sfn, mod); \
		continue; \
	}

/* 
 * This will run all the plugins per single user. When finished, it will call to delivery for local users.
 */
void *RunPerUserScannersAndDelivery(void *Data)
{
	char *plerror = NULL, *mod_name = NULL, *mod_version = NULL, *domain = NULL, config_file[PATH_MAX_NQQUEUE], mod[PATH_MAX_NQQUEUE], File[PATH_MAX_NQQUEUE];
	int i = 0, ret = 0, nPlugins = 0, PerUserScanners = 0;
	void *mod_handler = NULL;
	PluginsConf *conf_array = NULL;
	ModReturn *returned = NULL;
	RSStruct *PerUserRunnedScanners = malloc(sizeof(RSStruct));
	Destinations tmp;
	PUStruct *me = (PUStruct *)Data;

	PerUserRunnedScanners[0].plugin_name == NULL;

	/* Get the domain name of this destination */
	if ((domain = index(me->To, '@')))
	   	domain += 1;

	/* Initialize message file loop file */
	snprintf(File, PATH_MAX_NQQUEUE, "%s", me->File);

	/* Point the tmp union to this particular To */
	tmp.rcpt = me->To;

	/* Initialize the configuration file name using the general rules */
	if (!InitConf(domain, "nqqueue", 1, config_file)) {

		/* Load the configuration strings array */
		conf_array = Str2Conf(config_file, me->To, &nPlugins);

		for (i = 0; i < nPlugins && ret != 1; i++) {

			/* Get the full plugin name, PLUGINS_LOCATION/user/plugin_name.so */
			snprintf(mod, PATH_MAX_NQQUEUE, "%s/user/%s.so", PLUGINS_LOCATION, conf_array[i].plugin_name);

			/* Try to load the plugin */
			if ((mod_handler = dlopen(mod, RTLD_NOW)) == NULL) {
				debug(3, "nqqueue: error can't open plugin %s.so\n", conf_array[i].plugin_name);
				debug(5, "nqqueue: error: %s\n", dlerror());

				/* This should be configurable in the future: If can't open plugin, then try the next one... Or die? */
				/*_exit(EXIT_400);*/
				continue;
			}
			/* Clear errors and point the symbols of the desired plugin */
			dlerror();

			/* Load all our plugin functions */
			dynamic_symbol_resolution(mod_handler, conf_array[i].start.plugin_name, "plugin_name")
			dynamic_symbol_resolution(mod_handler, conf_array[i].start.plugin_version, "plugin_version")
			dynamic_symbol_resolution(mod_handler, conf_array[i].start.plugin_init, "plugin_init")

			/* Save the plugin_name and plugin_version data */
			mod_name = conf_array[i].start.plugin_name();
			mod_version = conf_array[i].start.plugin_version();
			debug(2, "nqqueue: Loaded plugin: %s v%s\n", mod_name, mod_version);

			/* Heiya! Run it damn it! */
			if ((returned = conf_array[i].start.plugin_init(conf_array[i].plugin_params, File, MailFrom, tmp, GlobalRunnedScanners, PerUserRunnedScanners))) {
			
				/* if returned isn't NULL, then it could be rejected or accepted... Let's check it */
				if (returned->rejected) {

					/* Ok, if 1 was returned it is because the plugin rejected the message */
					debug(2, "nqqueue: Message from %s to %s rejected by %s\n", MailFrom, tmp.rcpt, mod_name);

					/* So remove File and leave */
					unlink(File);
					errno = 0;
					ret = 1;
				}
				else {
					debug(2, "nqqueue: Message from %s to %s accepted by %s\n", MailFrom, tmp.rcpt, mod_name);
					PerUserRunnedScanners = realloc(PerUserRunnedScanners, sizeof(RSStruct) * (PerUserScanners + 2));
					PerUserRunnedScanners[PerUserScanners].plugin_name = strdup(mod_name);
					PerUserRunnedScanners[PerUserScanners].plugin_version = strdup(mod_version);
					if (conf_array[i].plugin_params)
						PerUserRunnedScanners[PerUserScanners].plugin_params = strdup(conf_array[i].plugin_params);
					else
						PerUserRunnedScanners[PerUserScanners].plugin_params = NULL;
					
					PerUserRunnedScanners[PerUserScanners].returned =  returned->ret;
					PerUserScanners += 1;

					memset(PerUserRunnedScanners+PerUserScanners, '\0', sizeof(RSStruct));

					if (returned->NewFile) {
						strcpy(File, returned->NewFile);
						free(returned->NewFile);
					}
				}
				free(returned->message);
				free(returned);
			}
			dlclose(mod_handler);

			/* Since we have it already registered, free that memory */
			free(mod_name);
			free(mod_version);

			free(conf_array[i].plugin_name);
			free(conf_array[i].plugin_params);
		}
		free(conf_array);
	}

	/* If all plugins allowed the email, then make the delivery */
	if (!ret)
		delivery(me->To, File, PerUserRunnedScanners, PerUserScanners);

	/* End the thread in the right way */
	pthread_exit(NULL);
}

/* 
 * Run general plugins
 */
void RunGeneralScanners(char *OutputFile)
{
	int i = 0, ret = 0, nPlugins = 0;
	char *plerror = NULL, *mod_name = NULL, *mod_version = NULL, File[PATH_MAX_NQQUEUE], mod[PATH_MAX_NQQUEUE], config_file[PATH_MAX_NQQUEUE];
	void *mod_handler = NULL;
	PluginsConf *conf_array = NULL;
	ModReturn *returned;
	Destinations tmp;

	/* Initialize the configuration file name using the general rules */
	if (InitConf(NULL, "general", 1, config_file)) {
		snprintf(OutputFile, PATH_MAX_NQQUEUE, "%s", MESSAGE_FILE);
		return;
	}

	/* Initialize message file loop file */
	snprintf(File, PATH_MAX_NQQUEUE, "%s", MESSAGE_FILE);

	/* Point the tmp union to all the To's */
	tmp.RcptTos = RcptTo;

	/* Load the configuration strings array */
	conf_array = Str2Conf(config_file, IsLocal(MailFrom) ? MailFrom : NULL, &nPlugins);

	/* Let's go through every plugin */
	for (i = 0; i < nPlugins && ret != 1; i++) {

		/* Get the full plugin name, PLUGINS_LOCATION/general/plugin_name.so */
		snprintf(mod, PATH_MAX_NQQUEUE, "%s/general/%s.so", PLUGINS_LOCATION, conf_array[i].plugin_name);

		/* Try to load the plugin */
		if (!(mod_handler = dlopen(mod, RTLD_NOW))) {
			debug(3, "nqqueue: error can't open plugin %s.so\n", conf_array[i].plugin_name);
			debug(4, "nqqueue: error: %s\n", dlerror());

			/* This should be configurable in the future: If can't open plugin, then try the next one... Or die? */
			/*_exit(EXIT_400);*/
			continue;
		}
		/* Clear errors and point the symbols of the desired plugin */
		dlerror();

		/* Load all our plugin functions */
		dynamic_symbol_resolution(mod_handler, conf_array[i].start.plugin_name, "plugin_name")
		dynamic_symbol_resolution(mod_handler, conf_array[i].start.plugin_version, "plugin_version")
		dynamic_symbol_resolution(mod_handler, conf_array[i].start.plugin_init, "plugin_init")

		/* Save the plugin_name and plugin_version data. Free them before the next iteration */
		mod_name = conf_array[i].start.plugin_name();
		mod_version = conf_array[i].start.plugin_version();
		debug(2, "nqqueue: Loaded plugin: %s.so %s\n", mod_name);

		/* Heiya! Run it damn it! */
		if ((returned = conf_array[i].start.plugin_init(conf_array[i].plugin_params, File, MailFrom, tmp, GlobalRunnedScanners, NULL))) {

			/* if returned isn't NULL, then it could be rejected or accepted... Let's check it */
			if (returned->rejected) {

				/* Ok, if 1 was returned it is because the plugin rejected the message so tell that */
				debug(2, "nqqueue: Message from %s rejected by %s.so\n", MailFrom, mod_name);

				/* Send the rejected message back to qmail if any */
				if (returned->message) {
					snprintf(mod, 255 + 15 + sizeof(PLUGINS_LOCATION), "D%s", returned->message);
					ret = write(4, mod, strlen(mod));
					free(returned->message);
				}
				ret = 1;
			}
			else {

				/* Great, message accepted by the runned scanner */
				debug(2, "nqqueue: Message from %s accepted by %s.so\n", MailFrom, mod_name);

				/* Register this new scanner */
				GlobalRunnedScanners = realloc(GlobalRunnedScanners, sizeof(RSStruct) * (GlobalScanners + 2));
				GlobalRunnedScanners[GlobalScanners].plugin_name = strdup(mod_name);
				GlobalRunnedScanners[GlobalScanners].plugin_version = strdup(mod_version);
				if (conf_array[i].plugin_params)
					GlobalRunnedScanners[GlobalScanners].plugin_params = strdup(conf_array[i].plugin_params);
				GlobalRunnedScanners[GlobalScanners].returned = returned->ret;

				GlobalScanners += 1;

				/* Point the next one to NULL to say this is the last one for now */
				memset(GlobalRunnedScanners+GlobalScanners, '\0', sizeof(RSStruct));

				if (returned->NewFile) {
					strcpy(File, returned->NewFile);
					free(returned->NewFile);
				}
			}
			free(returned);
		}

		/* Since we have it already registered, free that memory */
		free(mod_name); mod_name = NULL;
		free(mod_version); mod_version = NULL;

		/* Free this element in the conf array since it was already runned */
		free(conf_array[i].plugin_name);
		free(conf_array[i].plugin_params);

		/* Close the plugin handler */
		dlclose(mod_handler);
	}

	/* Free the configuration array and the global configuration file as we are done here */
	free(conf_array);
	
	/* If the message was rejected, then just clean and exit */
	if (ret)
		exit_clean(EXIT_MSG);

	strncpy(OutputFile, File, PATH_MAX_NQQUEUE);
}

/* 
 * The main function... Don't ask :-D
 */
int main(int argc, char *argv[])
{
	char buffer[BIG_BUFF], *tmp = NULL, Msg[PATH_MAX_NQQUEUE];
	int ret, fd, i, tmpread;
	pthread_attr_t attrs;

#ifdef HAS_ULIMIT_NPROC
	struct rlimit limits;
#endif
	/* Only version check, nothing else */
	if (argc > 1 && (strcasecmp(argv[1], "-v") || strcasecmp(argv[1], "--version"))) {
		printf("nqqueue %s\n", VERSION);
		exit(0);
	}

	/* Before anything, initialize counters pointers and the return value */
	qstat = RcptTotal = LocalRcpt = RemoteRcpt = GlobalScanners = 0;
	GlobalRunnedScanners = malloc(sizeof(RSStruct));
	RcptTo = NULL;

	GlobalRunnedScanners[0].plugin_name == NULL;

#ifdef HAS_ULIMIT_NPROC
	/* Set ulimits to prevent hangs if it forks too many processes */
	getrlimit(RLIMIT_NPROC, &limits);
	limits.rlim_cur = 1024;
	setrlimit(RLIMIT_NPROC, &limits);
#endif

	umask(0022);

	/* Get the time, as we are gonna use it and set debug as desired */
	gettimeofday(&start, (struct timezone *)NULL);

	/* Get the debug information */
	if ((tmp = getenv("NQQUEUE_DEBUG")) != NULL)
		debug_flag = atoi(tmp);
	else
		debug_flag = 0;

	/* Since we have start, we can use that to create a directory */
	snprintf(indexdir, PATH_MAX_NQQUEUE, "%s/%ld.%ld.%ld", NQQUEUE_WORKDIR, start.tv_sec, start.tv_usec, (long int)getpid());
	if (mkdir(indexdir, 0750) == -1) {
		debug(3, "nqqueue: error (%d) creating %s directory to work\n", errno, indexdir);
		_exit(EXIT_400);
	}

	/* change to the new working directory */
	if (chdir(indexdir)) {
		debug(3, "nqqueue: error (%d) changing directory to workdir\n", errno);
		exit_clean(EXIT_400);
	}

	/* open a msg file to hold the email with index = 0 */
	if ((fd = open(MESSAGE_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1) {
		debug(3, "nqqueue: error (%d) opening msg file %s\n", errno, MESSAGE_FILE);
		exit_clean(EXIT_400);
	}

	/* read the email into the new file */
	while ((ret = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
		if (write(fd, buffer, ret) == -1) {
			debug(3, "nqqueue: error (%d) writing msg to %s\n", errno, MESSAGE_FILE);
			exit_clean(EXIT_400);
		}
	}
	/* If ret < 0 there was an error in the reading, so we abort */
	if (ret < 0) {
		debug(3, "nqqueue: error (%d) reading file from SMTP\n", errno);
		exit_clean(EXIT_400);
	}

	/* close the file */
	if (close(fd)) {
		debug(3, "nqqueue: error (%d) closing email file\n", errno);
		exit_clean(EXIT_400);
	}

	/* 
	 * READ THE ADDRESSES COMMING FROM THE 0 FILE DESCRIPTOR AND STORE THEM IN MEMORY
	 * THE FORMAT OF THE INCOMING DATA IS: AddrOrig\0TDestAddr1\0TDestAddr2\0T...\0
	 */

	while ((tmpread = read (STDOUT_FILENO, buffer, sizeof(buffer))) > 0) {
		/* Read the Origin Address */
		if (RcptTotal == 0)
			strlower(buffer+1, MailFrom);
		/* Next addr + \0 + T */
		for (i = 0; i < tmpread && buffer[i] != 0; ++i) ; i += 2;

		while (i < tmpread) {
			RcptTo = realloc(RcptTo, (RcptTotal+1) * sizeof(PUStruct));
			strlower(buffer+i, RcptTo[RcptTotal].To);
			RcptTo[RcptTotal].deliver = 1;
			for (; i < tmpread && buffer[i] != 0; ++i) ; i += 2;
			RcptTotal += 1;
		}
		memset (buffer, '\0', tmpread);
	}

	/* Sanity check point 1 to see if qmail-smtpd died for unknown reasons */
	if (getppid() == 1) {
		debug(3, "nqqueue: parent died, exiting\n");
		exit_clean(EXIT_0);   /* <---- This is kinda hilarious */
	}

	/* Sanity check point 2 check if we are missing origin and/or destination addresses */
	if (*MailFrom == '\0' || RcptTotal == 0) {
		debug(3, "nqqueue: got empty data, exiting with error code: %d\n", EXIT_400);
		exit_clean(EXIT_400);
	}

	/* First part of the scanning process: General Scanners */
	RunGeneralScanners(Msg);

	pthread_attr_init(&attrs);
	pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_JOINABLE);

	for (i = 0; i < RcptTotal; i++) {
		if (IsLocal(RcptTo[i].To)) {
			snprintf(buffer, PATH_MAX_NQQUEUE, "%s.%s", Msg, RcptTo[i].To);
			copy(Msg, buffer);
			strncpy(RcptTo[i].File, buffer, PATH_MAX_NQQUEUE);
			RcptTo[i].deliver = 0;
			LocalRcpt += 1;
			if (pthread_create(&(RcptTo[i].Index), &attrs, RunPerUserScannersAndDelivery, RcptTo + i) != 0)
				debug(3, "nqqueue: error (%d) creating thread\n", errno);
		}
		else {
			RemoteRcpt += 1;
		}
	}

	/* Do the general delivery to those remote users */
	if (RemoteRcpt > 0)
		deliveryAll(Msg);

	/* Wait for all per user scanners threads to finish scanning + delivery */
	for (i = 0; i < RcptTotal; i++)
		if (!RcptTo[i].deliver)
			pthread_join(RcptTo[i].Index, NULL);

	/* Free the RcptTo array and the MailFrom pointer */
	free(RcptTo);

	debug(4, "nqqueue: removing files used in the analysis\n");
	/* remove the working files */
	if (remove_files(indexdir) == -1)
		exit_clean(EXIT_400);

	debug(4, "nqqueue: exiting nqqueue with status: %d\n", WEXITSTATUS(qstat));
	/* pass qmail-queue's exit status from deliveryAll on */
	exit(WEXITSTATUS(qstat));

	/* suppress warning messages */
	return 0;
}
