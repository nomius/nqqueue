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

#include "config.h"

/* Comparison macro */
#define STARTSWITH(x,y) (!strncmp(x, y, ((strlen(x))>(strlen(y))? (strlen(y)):(strlen(x)))))

/* Structures needed for plugin's configuration */
typedef struct stNPlugin {
	/* Function that returns an allocated char pointer with the plugin name */
	char *(*plugin_name) (void);
	/* Function that returns an allocated char pointer with the plugin version */
	char *(*plugin_version) (void);
	/* Initial function. Arguments: params, mail, From, Rcpt, general, PerUser */
	ModReturn *(*plugin_init) (char *, const char *, const char *, const Destinations, RSStruct *, RSStruct *);
} NPlugin;

typedef struct stPluginsConf {
	char *plugin_name;
	char *plugin_params;
	NPlugin start;
} PluginsConf;

int InitConf(char *domain, char *fallback_name, int TryGetEnv, char *config_file);
int GetConfLine(char *matchconf, char *addr, char *config_file);
PluginsConf *Str2Conf(char *config_file, char *user, int *mods);

