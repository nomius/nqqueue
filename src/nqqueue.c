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
#include "nqqueue.h"
#include "general.h"
#include "delivery.h"
#include "cfg.h"

/* 
 * Load plugin symbols
 */
struct plugin *symbols_load(void *handler, char *mod)
{
	const char *errmsg;
	struct plugin *init;

	/* Create a structure for the plugins */
	init = calloc(1, sizeof(struct plugin));

	/* Load the plugin and point every function to its address */
	init->plugin_name = dlsym(handler, "plugin_name");
	if ((errmsg = dlerror()) != NULL) {
		debug(4, "nqqueue: error (%d) no plugin_name symbol found in %s\n", errno, mod);
		free(init);
		return NULL;
	}

	init->plugin_version = dlsym(handler, "plugin_version");
	if ((errmsg = dlerror()) != NULL) {
		debug(4, "nqqueue: error (%d) no plugin_version symbol found in %s\n", errno, mod);
		free(init);
		return NULL;
	}
	init->plugin_init = dlsym(handler, "plugin_init");
	if ((errmsg = dlerror()) != NULL) {
		debug(4, "nqqueue: error (%d) no plugin_init symbol found in %s\n", errno, mod);
		free(init);
		return NULL;
	}
	return init;
}

/* 
 * This will run all the plugins per single user. When finished, it will call to delivery for local users.
 */
void *RunPerUserScannersAndDelivery(void *Data)
{
	int i = 0;
	int ret = 0;
	int nPlugins;
	int PerUserScanners = 1;
	void *mod_handler;
	struct conf *conf_array = NULL;
	struct ModReturn *returned;
	struct PUStruct *me = (struct PUStruct *)Data;
	char *mod_name, *mod_version;
	char *File = calloc(255, sizeof(char));
	char mod[sizeof(PLUGINS_LOCATION) + 255 + 15];
	char *domain = index(me->To, '@') + 1;
	char *config_file = InitConf(domain, "nqqueue", 1);
	struct RSStruct *PerUserRunnedScanners;
	union Tos tmp;

	sprintf(File, "%s", me->File);
	free(me->File);
	tmp.rcpt = me->To;

	PerUserRunnedScanners = malloc(sizeof(struct RSStruct));
	PerUserRunnedScanners[PerUserScanners - 1].plugin_name = NULL;

	if (config_file != NULL) {

		/* Great, we have configuration file, so load it and the conf itself */
		conf_array = Str2Conf(GetConfLine(me->To, config_file), &nPlugins);

		for (i = 0; i < nPlugins && ret != 1; i++) {

			/* Get the full plugin name, PLUGINS_LOCATION/user/plugin_name.so */
			sprintf(mod, "%s/user/%s.so", PLUGINS_LOCATION, conf_array[i].plugin_name);

			/* Try to load the plugin */
			if ((mod_handler = dlopen(mod, RTLD_NOW)) == NULL) {
				debug(3, "nqqueue: error (%d) can't open plugin %s.so\n", errno, conf_array[i].plugin_name);
				debug(5, "nqqueue: error: %s\n", dlerror());

				/* This should be configurable in the future: If can't open plugin, then try the next one... Or die? */
				/*_exit(EXIT_400);*/
				continue;
			}

			/* Clear errors and point the symbols of the desired  plugin */
			dlerror();
			if ((conf_array[i].start = symbols_load(mod_handler, conf_array[i].plugin_name)) == NULL)
				continue;

			/* Save the plugin_name and plugin_version data */
			mod_name = conf_array[i].start->plugin_name();
			mod_version = conf_array[i].start->plugin_version();
			debug(2, "nqqueue: Loaded plugin: %s.so\n", mod_name);

			/* Heiya! Run it damn it! */
			returned = conf_array[i].start->plugin_init(conf_array[i].plugin_params, File, MailFrom, tmp, GlobalRunnedScanners, PerUserRunnedScanners);

			/* if returned is NULL, then I suppose there was an error. So no register is made */
			if (returned) {
				if (returned->rejected) {

					/* Ok, if 1 was returned it is because the plugin rejected the message */
					if (!strcmp(MailFrom, ""))
						debug(2, "nqqueue: Message from anonymous sender to %s rejected by %s.so\n", tmp.rcpt, mod_name);
					else
						debug(2, "nqqueue: Message from %s to %s rejected by %s.so\n", MailFrom, tmp.rcpt, mod_name);

					/* So remove File, free the To and leave */
					unlink(File);
					errno = 0;
					free(me->To);
					ret = 1;
				}
				else {
					if (!strcmp(MailFrom, ""))
						debug(2, "nqqueue: Message from anonymous sender to %s accepted by %s.so\n", tmp.rcpt, mod_name);
					else
						debug(2, "nqqueue: Message from %s to %s accepted by %s.so\n", MailFrom, tmp.rcpt, mod_name);
					PerUserRunnedScanners = realloc(PerUserRunnedScanners, sizeof(struct RSStruct) * PerUserScanners + 1);
					PerUserRunnedScanners[PerUserScanners - 1].plugin_name = strdup(mod_name);
					PerUserRunnedScanners[PerUserScanners - 1].plugin_version = strdup(mod_version);
					if (conf_array[i].plugin_params)
						PerUserRunnedScanners[PerUserScanners - 1].plugin_params = strdup(conf_array[i].plugin_params);
					PerUserRunnedScanners[PerUserScanners - 1].returned = returned->ret;
					PerUserRunnedScanners[PerUserScanners].plugin_name = NULL;
					PerUserScanners += 1;

					if (returned->NewFile) {
						free(File);
						File = strdup(returned->NewFile);
						free(returned->NewFile);
					}
				}
				free(returned);
			}
			dlclose(mod_handler);
			free(mod_name);
			free(mod_version);
			free(conf_array[i].plugin_name);
			if (conf_array[i].plugin_params)
				free(conf_array[i].plugin_params);
			free(conf_array[i].start);
		}
		if (conf_array)
			free(conf_array);
		free(config_file);
	}

	/* If all plugins allowed the email, then make the delivery */
	if (ret == 0)
		delivery(me->To, File, PerUserRunnedScanners, PerUserScanners);

	/* End the thread in the right way */
	me->Index = (pthread_t)-1;
	pthread_exit(NULL);
}

/* 
 * Run general plugins
 */
char *RunGeneralScanners()
{
	int i = 0;
	int ret = 0;
	int nPlugins;
	void *mod_handler;
	char *mod_name, *mod_version;
	char *File = calloc(255, sizeof(char));
	char mod[sizeof(PLUGINS_LOCATION) + 255 + 15];
	char *config_file = InitConf(NULL, "general", 0);
	struct conf *conf_array = NULL;
	struct ModReturn *returned;
	union Tos tmp;

	/* Initialize message file */
	sprintf(File, "%s", MESSAGE_FILE);

	/* Initialize GlobalRunnedScanners pointer */
	GlobalScanners = 1;
	GlobalRunnedScanners = malloc(sizeof(struct RSStruct));
	GlobalRunnedScanners[GlobalScanners - 1].plugin_name = NULL;

	if (config_file != NULL) {

		/* Point the tmp union to all the To's */
		tmp.RcptTos = RcptTo;

		/* Great, we have configuration file, so load it depending if the sender is local or not */
		if (IsLocal(MailFrom))
			conf_array = Str2Conf(GetConfLine(MailFrom, config_file), &nPlugins);
		else
			conf_array = Str2Conf(GetConfLine(NULL, config_file), &nPlugins);

		for (i = 0; i < nPlugins && ret != 1; i++) {

			/* Get the full plugin name, PLUGINS_LOCATION/general/plugin_name.so */
			sprintf(mod, "%s/general/%s.so", PLUGINS_LOCATION, conf_array[i].plugin_name);

			/* Try to load the plugin */
			if ((mod_handler = dlopen(mod, RTLD_NOW)) == NULL) {
				debug(3, "nqqueue: error (%d) can't open plugin %s.so\n", errno, conf_array[i].plugin_name);
				debug(4, "nqqueue: error: %s\n", dlerror());

				/* This should be configurable in the future: If can't open plugin, then try the next one... Or die? */
				/*_exit(EXIT_400);*/
				continue;
			}

			/* Clear errors and point the symbols of the desired plugin */
			dlerror();
			if ((conf_array[i].start = symbols_load(mod_handler, conf_array[i].plugin_name)) == NULL)
				continue;

			/* Save the plugin_name and plugin_version data. Free them before the next iteration */
			mod_name = conf_array[i].start->plugin_name();
			mod_version = conf_array[i].start->plugin_version();
			debug(2, "nqqueue: Loaded plugin: %s.so\n", mod_name);

			/* Heiya! Run it damn it! */
			returned = conf_array[i].start->plugin_init(conf_array[i].plugin_params, File, MailFrom, tmp, GlobalRunnedScanners, NULL);

			/* if returned is NULL, then I suppose there was an error. So no register is made */
			if (returned) {
				if (returned->rejected) {

					/* Ok, if 1 was returned it is because the plugin rejected the message so tell that */
					if (!strcmp(MailFrom, ""))
						debug(2, "nqqueue: Message from anonymous sender rejected by %s.so\n", mod_name);
					else
						debug(2, "nqqueue: Message from %s rejected by %s.so\n", MailFrom, mod_name);

					/* Print the message if any, free the MailFrom and finish */
					if (returned->message != NULL) {
						snprintf(mod, 255 + 15 + sizeof(PLUGINS_LOCATION), "D%s", returned->message);
						write(4, mod, strlen(mod));
						free(returned->message);
					}
					if (MailFrom)
						free(MailFrom);
					ret = 1;
				}
				else {

					/* Great, message accepted by the runned scanner */
					if (!strcmp(MailFrom, ""))
						debug(2, "nqqueue: Message from anonymous sender accepted by %s.so\n", mod_name);
					else
						debug(2, "nqqueue: Message from %s accepted by %s.so\n", MailFrom, mod_name);

					/* Register this new scanner */
					GlobalRunnedScanners = realloc(GlobalRunnedScanners, sizeof(struct RSStruct) * GlobalScanners + 1);
					GlobalRunnedScanners[GlobalScanners - 1].plugin_name = strdup(mod_name);
					GlobalRunnedScanners[GlobalScanners - 1].plugin_version = strdup(mod_version);
					if (conf_array[i].plugin_params)
						GlobalRunnedScanners[GlobalScanners - 1].plugin_params = strdup(conf_array[i].plugin_params);
					GlobalRunnedScanners[GlobalScanners - 1].returned = returned->ret;

					/* Point the next one to NULL to say this is the last one for now */
					GlobalRunnedScanners[GlobalScanners].plugin_name = NULL;
					GlobalScanners += 1;

					if (returned->NewFile) {
						free(File);
						File = strdup(returned->NewFile);
						free(returned->NewFile);
					}
				}
				free(returned);
			}

			/* Since we have it already registered, free that memory */
			free(mod_name);
			free(mod_version);

			/* Free this element in the conf array since it was already runned */
			free(conf_array[i].plugin_name);
			if (conf_array[i].plugin_params)
				free(conf_array[i].plugin_params);

			/* Free the start structure */
			free(conf_array[i].start);

			/* Close the plugin handler */
			dlclose(mod_handler);
		}

		/* Free the configuration array and the global configuration file as we are done here */
		if (conf_array)
			free(conf_array);
		free(config_file);
	}
	/* If the message was rejected, then just clean and exit */
	if (ret == 1)
		exit_clean(EXIT_MSG);
	return File;
}

/* 
 * The main function... Don't ask :-D
 */
int main(int argc, char **argv)
{
	int pim[2];
	char *buffer;
	char *RcptToLocal;
	char *new_file;
	char *Msg;
	int ret;
	int fd;
	int tmpread;
	int i;
	int pid;

#ifdef HAS_ULIMIT_NPROC
	struct rlimit limits;
#endif

	/* Only version check, nothing else */
	if (argv[1] != NULL && (strcasecmp(argv[1], "-v") || strcasecmp(argv[1], "--version"))) {
		printf("nqqueue %s\n", VERSION);
		exit(0);
	}

	/* Before anything, set qstat to 0 in case we have no delivery to do */
	qstat = 0;

#ifdef HAS_ULIMIT_NPROC
	/* Set ulimits to prevent hangs if it forks too many processes */
	getrlimit(RLIMIT_NPROC, &limits);
	limits.rlim_cur = 1024;
	setrlimit(RLIMIT_NPROC, &limits);
#endif

	umask(0022);

	/* Get the time, as we are gonna use it and set debug as desired */
	gettimeofday(&start, (struct timezone *)0);
	if ((buffer = getenv("NQQUEUE_DEBUG")) != NULL)
		debug_flag = atoi(buffer);
	else
		debug_flag = 0;

	/* Since we have start, we can use that to create a directory */
	indexdir = calloc(SMALL_BUFF, sizeof(char));
	snprintf(indexdir, SMALL_BUFF, "%s/%ld.%ld.%ld", NQQUEUE_WORKDIR, start.tv_sec, start.tv_usec, (long int)getpid());
	if (mkdir(indexdir, 0750) == -1) {
		debug(3, "nqqueue: error (%d) creating %s directory to work\n", errno, indexdir);
		_exit(EXIT_400);
	}

	/* change to the new working directory */
	if (chdir(indexdir) != 0) {
		debug(3, "nqqueue: error (%d) changing directory to workdir\n", errno);
		exit_clean(EXIT_400);
	}

	/* open a msg file to hold the email with index = 0 */
	if ((fd = open(MESSAGE_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1) {
		debug(3, "nqqueue: error (%d) opening msg file %s\n", errno, MESSAGE_FILE);
		exit_clean(EXIT_400);
	}

	/* read the email into the new file */
	buffer = calloc(sizeof(char), SMALL_BUFF);
	while ((ret = read(0, buffer, sizeof(buffer))) > 0) {
		if (write(fd, buffer, ret) == -1) {
			debug(3, "nqqueue: error (%d) writing msg\n", errno);
			exit_clean(EXIT_400);
		}
		memset(buffer, 0, ret);
	}
	free(buffer);

	/* close the file */
	if (close(fd) == -1) {
		debug(3, "nqqueue: error (%d) closing email file\n", errno);
		exit_clean(EXIT_400);
	}

	/* read/write in the email addresses and put them in memory */
	buffer = calloc(sizeof(char), SMALL_BUFF);
	RcptTotal = 0;
	MailFrom = NULL;
	RcptTo = NULL;
	while ((tmpread = read(1, buffer, SMALL_BUFF - 1)) > 0) {
		if (RcptTotal == 0) {
			MailFrom = strdup(buffer + 1);
			strlower(MailFrom);
		}
		for (i = 0; i < tmpread && buffer[i] != 0; ++i) ;
		i += 2;
		while (i < tmpread) {
			RcptTotal += 1;
			RcptTo = realloc(RcptTo, RcptTotal * sizeof(struct PUStruct));
			RcptTo[RcptTotal - 1].To = strdup(&(buffer[i]));
			strlower(RcptTo[RcptTotal - 1].To);
			RcptTo[RcptTotal - 1].Index = 0;
			while (i < tmpread && buffer[i] != 0)
				i++;
			i += 2;
		}
		memset(buffer, 0, tmpread);
	}
	free(buffer);

	if (getppid() == 1) {
		debug(3, "nqqueue: parent died, exiting\n");
		exit_clean(EXIT_0);
	}

	if (MailFrom == NULL && RcptTo == NULL) {
		debug(3, "nqqueue: got empty data, exiting with error code: %d\n", EXIT_400);
		exit_clean(EXIT_400);
	}

	LocalRcpt = RemoteRcpt = 0;

	Msg = RunGeneralScanners();

	for (i = 0; i < RcptTotal; i++) {
		if (IsLocal(RcptTo[i].To)) {
			new_file = calloc(strlen(Msg) + 2 + strlen(RcptTo[i].To), sizeof(char));
			sprintf(new_file, "%s.%s", Msg, RcptTo[i].To);
			new_file[strlen(new_file)] = 0;
			copy(Msg, new_file);
			RcptTo[i].File = new_file;
			RcptTo[i].Index = (pthread_t)-1;
			LocalRcpt += 1;
			if (pthread_create(&(RcptTo[i].Index), NULL, RunPerUserScannersAndDelivery, RcptTo + i) != 0)
				debug(3, "nqqueue: error (%d) creating thread\n", errno);
		}
		else {
			RcptTo[i].Index = (pthread_t)-1;
			RemoteRcpt += 1;
		}
	}

	/* Do the general delivery to those remote users */
	if (RemoteRcpt > 0)
		deliveryAll(Msg);

	/* Wait for all the per user scanners threads */
	for (i = 0; i < RcptTotal; i++)
		if (RcptTo[i].Index != (pthread_t)-1)
			pthread_join(RcptTo[i].Index, NULL);

	/* Free the RcptTo array and the MailFrom pointer */
	free(RcptTo);
	free(MailFrom);

	debug(4, "removing files used in the analysis\n");
	/* remove the working files */
	if (remove_files(indexdir) == -1)
		exit_clean(EXIT_400);

	free(indexdir);

	debug(4, "exiting nqqueue with status: %d\n", WEXITSTATUS(qstat));
	/* pass qmail-queue's exit status from deliveryAll on */
	exit(WEXITSTATUS(qstat));

	/* suppress warning messages */
	return 0;
}
