/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Clipboard Files Stealer
 *
 * Copyright 2019 Kobi Mizrachi <kmizrachi18@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <winpr/wtypes.h>
#include <winpr/file.h>
#include <winpr/collections.h>
#include <freerdp/log.h>

#include "pf_stealer.h"

BOOL pf_stealer_set_files(pfClipboard* clipboard, FILEDESCRIPTOR* descriptors, UINT count)
{
	// TODO only create streams for real files (not dirs)
	void* tmp;

	if (clipboard->descriptors)
		free(clipboard->descriptors);

	if (clipboard->streams)
	{
		free(clipboard->streams);
		clipboard->streams = NULL;
	}

	clipboard->descriptors = descriptors;
	clipboard->nstreams = count;

	tmp = realloc(clipboard->streams, count * sizeof(fileStream));
	if (!tmp)
	{
		if (clipboard->streams)
		{
			free(clipboard->streams);
			clipboard->streams = NULL;
		}

		return FALSE;
	}

	clipboard->streams = tmp;
	ZeroMemory(clipboard->streams, clipboard->nstreams * sizeof(fileStream));
	return TRUE;
}

pfClipboard* pf_stealer_new(CliprdrServerContext* server, CliprdrClientContext* client)
{
	pfClipboard* pfc;

	pfc = (pfClipboard*)calloc(1, sizeof(pfClipboard));
	if (!pfc)
		return NULL;

	pfc->req_fevent = CreateEvent(NULL, TRUE, FALSE, NULL);

	pfc->server = server;
	pfc->client = client;
	return pfc;
}

void pf_stealer_free(pfClipboard* clipboard)
{
	size_t i;

	free(clipboard->descriptors);
	clipboard->descriptors = NULL;

	for (i = 0; i < clipboard->nstreams; i++)
	{
		if (clipboard->streams[i].data)
			free(clipboard->streams[i].data);
	}

	free(clipboard->streams);
	clipboard->streams = NULL;
}
