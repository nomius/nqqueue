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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <nqqueue.h>

#define PLUGIN_VERSION "1.0"
#define PLUGIN_NAME "black"
#define REJECTED_MESSAGE "Message rejected because of black list"

char *plugin_name()
{
	return strdup(PLUGIN_NAME);
}

char *plugin_version()
{
	return strdup(PLUGIN_VERSION);
}

struct ModReturn *plugin_init(char *params, const char *mail, const char *From, const union Tos Rcpt, struct RSStruct *general, struct RSStruct *peruser)
{
	struct ModReturn *ret = malloc(sizeof(struct ModReturn));

	ret->NewFile = NULL;
	if (strcmp(From, "") && !strcmp(params, From)) {
		ret->ret = 1;
		ret->rejected = 1;
		ret->message = strdup(REJECTED_MESSAGE);
	}
	else {
		ret->ret = 0;
		ret->rejected = 0;
		ret->message = NULL;
	}
	return ret;
}
