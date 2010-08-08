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
char *InitConf(char *domain, char *fallback_name, int TryGetEnv)
{
	char *test;
	char *config_file;
	FILE *testing;

	if (TryGetEnv) {

		/* If getenv gives us something we use that */
		if ((test = getenv("NQQFILE")) != NULL) {
			config_file = calloc(strlen(test) + strlen(CONTROLDIR) + 6, sizeof(char));
			sprintf(config_file, "%s/%s.cfb", CONTROLDIR, test);
			if (((testing = fopen(config_file, "r")) != NULL)) {
				debug(2, "nqqueue: using environment configuration file: %s\n", test);
				fclose(testing);
				return config_file;
			}
			free(config_file);
		}
	}

	/* So, no config file defined or couldn't open it. Try domain file */
	if (domain != NULL) {
		config_file = calloc(strlen(domain) + strlen(CONTROLDIR) + 6, sizeof(char));
		sprintf(config_file, "%s/%s.cfb", CONTROLDIR, domain);
		if ((testing = fopen(config_file, "r")) != NULL) {
			debug(2, "nqqueue: using domain configuration file: %s\n", domain);
			fclose(testing);
			return config_file;
		}
		errno = 0;
		free(config_file);
	}

	/* So, final try, let's see if there is a general file, otherwise return NULL */
	config_file = calloc(13 + strlen(CONTROLDIR), sizeof(char));
	sprintf(config_file, "%s/%s.cfb", CONTROLDIR, fallback_name);
	if ((testing = fopen(config_file, "r")) != NULL) {
		debug(2, "nqqueue: using fallback configuration file: %s\n", fallback_name);
		fclose(testing);
		return config_file;
	}
	errno = 0;

	/* Oooops, dude give me something, otherwise you are doing qmail-queue's work twice */
	free(config_file);
	debug(2, "nqqueue: no configuration file found\n");
	return NULL;
}

/* 
 * This function parse the configuration file returning the given line
 */
char *GetConfLine(const char *user, const char *config_file)
{
	FILE *fp;
	char *l;
	char *general;
	char *str;
	char *buffer_str;
	char *domain;
	char *domain_str = NULL, *user_str = NULL, *general_str = NULL;

	buffer_str = calloc(sizeof(char), BUFFER_BIG);

	if (!config_file)
		return NULL;
	if (user == NULL)
		domain = NULL;
	else {
		if ((domain = index(user, '@')) != NULL)
			domain += 1;
		else
			domain = NULL;
	}

	if ((fp = fopen(config_file, "r")) == NULL) {
		debug(3, "nqqueue: error(%d) trying to open: %s\n", errno, config_file);
		exit_clean(EXIT_400);
	}

	while (fgets(buffer_str, BUFFER_BIG, fp) != NULL) {
		if (buffer_str[0] == ':')
			general_str = strdup(buffer_str + 1);
		else if (domain != NULL && CheckRegex(domain, buffer_str))
			domain_str = strdup(strchr(buffer_str, ':') + 1);
		else if (user != NULL && CheckRegex(user, buffer_str)) {
			user_str = strdup(strchr(buffer_str, ':') + 1);
			break;
		}
		if (user == NULL && domain_str != NULL)
			break;
		if (user == NULL && domain == NULL && general_str != NULL)
			break;
	}

	fclose(fp);
	free(buffer_str);

	if (user_str) {
		if (domain_str)
			free(domain_str);
		if (general_str)
			free(general_str);
		return user_str;
	}
	if (domain_str) {
		if (general_str)
			free(general_str);
		return domain_str;
	}
	if (general_str)
		return general_str;

	return NULL;
}

int CheckRegex(char *needed, char *ToUseRegex)
{
#ifdef HAVE_REGEXEC
	regex_t re;
	int ret = 0;
	char *ptr = NULL;
	char *rgx = strdup(ToUseRegex);

	if ((ptr = strchr(rgx, ':')) != NULL)
		*ptr = 0;
	else
		rgx[strlen(rgx)] = 0;

	if(regcomp(&re, rgx, REG_EXTENDED|REG_ICASE) == 0)
		if(regexec(&re, needed, 0, NULL, 0) == 0)
			ret = 1;
		else
			ret = 0;
	free(rgx);
	return ret;
#else
	return STARTSWITH(needed, ToUseRegex);
#endif
}


/* 
 * This function parse the line and create the user configuration array
 */
struct conf *Str2Conf(char *string, int *mods)
{
	char *token = string, *equal, *init = string;
	struct conf *ret = NULL;
	int j;

	if (string == NULL) {
		*mods = 0;
		return NULL;
	}
	*mods = 0;
	for (j = 0; token != NULL; j++, string = NULL) {
		token = strtok(string, ";");
		if (token != NULL) {
			ret = realloc(ret, sizeof(struct conf) * (j + 1));
			equal = index(token, '=');
			if (equal != NULL) {
				ret[j].plugin_params = strdup(alltrim(equal + 1));
				if (ret[j].plugin_params[strlen(ret[j].plugin_params) - 1] == '\n')
					ret[j].plugin_params[strlen(ret[j].plugin_params) - 1] = 0;
				*equal = 0;
			}
			else
				ret[j].plugin_params = NULL;
			ret[j].plugin_name = strdup(alltrim(token));
			if (ret[j].plugin_name[strlen(ret[j].plugin_name) - 1] == '\n')
				ret[j].plugin_name[strlen(ret[j].plugin_name) - 1] = 0;
			(*mods) += 1;
			debug(2, "nqqueue: Loading settings for plugin %s.so\n", ret[j].plugin_name);
		}
	}
	free(init);
	return ret;
}

