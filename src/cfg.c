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
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <pthread.h>
#include "nqqueue.h"
#include "general.h"
#include "cfg.h"

#ifdef HAVE_REGEXEC
#include <regex.h>
#endif

/* 
 * Get the configuration file from the NQQFILE or goes to fallback
 */
int InitConf(char *domain, char *fallback_name, int TryGetEnv, char *config_file)
{
	char *test = NULL;
	FILE *testing;

	if (TryGetEnv) {
		/* If getenv gives us something we use that */
		if ((test = getenv("NQQFILE")) != NULL) {
			snprintf(config_file, PATH_MAX_NQQUEUE, "%s/%s.cfb", CONTROLDIR, test);
			if ((testing = fopen(config_file, "r")) != NULL) {
				debug(2, "nqqueue: using environment configuration file: %s\n", test);
				fclose(testing);
				return 0;
			}
		}
	}
	errno = 0;

	/* So, no config file defined or couldn't open it. Try domain file */
	if (domain) {
		snprintf(config_file, PATH_MAX_NQQUEUE, "%s/%s.cfb", CONTROLDIR, domain);
		if ((testing = fopen(config_file, "r")) != NULL) {
			debug(2, "nqqueue: using domain configuration file: %s\n", domain);
			fclose(testing);
			return 0;
		}
	}
	errno = 0;

	/* So, final try, let's see if there is a general file, otherwise return NULL */
	snprintf(config_file, PATH_MAX_NQQUEUE, "%s/%s.cfb", CONTROLDIR, fallback_name);
	if ((testing = fopen(config_file, "r")) != NULL) {
		debug(2, "nqqueue: using fallback configuration file: %s\n", fallback_name);
		fclose(testing);
		return 0;
	}
	errno = 0;

	/* Oooops, dude give me something, otherwise you are doing qmail-queue's work twice */
	debug(2, "nqqueue: no configuration file found\n");
	return 1;
}

/* 
 * This function parse the configuration file returning the given line
 */
int GetConfLine(char *matchconf, char *addr, char *config_file)
{
	FILE *fp;
	char *domain = NULL, *domain_str = NULL, *user_str = NULL, *general_str = NULL, *tmp = NULL, buffer[BIG_BUFF];
	int ret = 0;

	*matchconf = '\0';

	if (addr) {
		if ((domain = strchr(addr, '@'))) {
			if (domain + 1) {
				domain += 1;
			}
		}
		else {
			domain = NULL;
		}
	}
	else {
		domain = NULL;
	}

	if (!(fp = fopen(config_file, "r"))) {
		debug(3, "nqqueue: error(%d:%s) trying to open: %s\n", errno, strerror(errno), config_file);
		exit_clean(EXIT_400);
	}

	while (fgets(buffer, BIG_BUFF, fp)) {

		if (!*buffer)
			continue;

		/* General file configuration */
		if (*buffer == ':' && *(buffer + 1))
			general_str = strdup(buffer + 1);

		/* Domain configuration */
		else if (domain && CheckRegex(domain, buffer)) {
			if ((tmp = strchr(buffer, ':')))
				if (*(tmp+1))
					domain_str = strdup(tmp);
		}

		/* User exact configuration */
		else if (addr && CheckRegex(addr, buffer)) {
			if ((tmp = strchr(buffer, ':')))
				if (*(tmp+1)) {
					user_str = strdup(tmp);
					break;
				}
		}
	}

	fclose(fp);

	if (user_str)
		strncpy(matchconf, user_str, BIG_BUFF);
	else if (domain_str)
		strncpy(matchconf, domain_str, BIG_BUFF);
	else if (general_str)
		strncpy(matchconf, general_str, BIG_BUFF);
	else
		ret = 1;
	
	free(user_str); free(domain_str); free(general_str);

	return ret;
}

int CheckRegex(char *needed, char *ToUseRegex)
{
#ifdef HAVE_REGEXEC
	regex_t re;
	int ret = 0;
	char rgx[BIG_BUFF];
   
	if (!needed)
		return 0;

	strncpy(rgx, ToUseRegex, BIG_BUFF);

	if(!regcomp(&re, rgx, REG_EXTENDED|REG_ICASE)) {
		if(!regexec(&re, needed, 0, NULL, 0))
			ret = 1;
		else
			ret = 0;
	}
	return ret;
#else
	return STARTSWITH(needed, ToUseRegex);
#endif
}


/* 
 * This function parse the line and create the user configuration array
 */
PluginsConf *Str2Conf(char *config_file, char *user, int *mods)
{
	char *token = NULL, *equal = NULL, matchconf[BIG_BUFF], *string = NULL;
	int j = 0;
	PluginsConf *ret = NULL;

	*mods = 0;
	if (GetConfLine(matchconf, user, config_file))
		return NULL;

	string = matchconf;

	for (j = 0; (token = strtok(string, ";")); string = NULL, j++) {
		if (*token == '\0' || *token == '\n')
			continue;
		ret = realloc(ret, sizeof(PluginsConf) * (j + 1));
		memset(ret+j, '\0', sizeof(PluginsConf));
		if ((equal = strchr(token, '='))) {
			if (*(equal + 1)) {
				ret[j].plugin_params = strdup(alltrim(equal + 1));
				if (ret[j].plugin_params[strlen(ret[j].plugin_params) - 1] == '\n')
					ret[j].plugin_params[strlen(ret[j].plugin_params) - 1] = '\0';
				*equal = '\0';
			}
			else
				ret[j].plugin_params = NULL;
		}
		else
			ret[j].plugin_params = NULL;
		ret[j].plugin_name = strdup(alltrim(token));
		if (ret[j].plugin_name[strlen(ret[j].plugin_name) - 1] == '\n')
			ret[j].plugin_name[strlen(ret[j].plugin_name) - 1] = '\0';
		(*mods) += 1;
		debug(2, "nqqueue: Loading settings for plugin %s.so\n", ret[j].plugin_name);
	}
	return ret;
}

