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
	void* tmp;

	if (clipboard->descriptors)
		free(clipboard->descriptors);

	if (clipboard->stolen_files)
	{
		free(clipboard->stolen_files);
		clipboard->stolen_files = NULL;
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

BOOL pf_stealer_write_file(pfClipboard* clipboard, UINT32 listIndex, const BYTE* data, UINT32 len)
{
	stolenFile* file;
	FILEDESCRIPTOR descriptor;
	UINT32 written;

	if (listIndex >= clipboard->nstreams)
		return FALSE;

	file = &clipboard->stolen_files[listIndex];
	descriptor = clipboard->descriptors[listIndex];

	if (file->handle == NULL)
	{
		printf("opening file\n");
		/* open file */
		file->handle = CreateFileW(descriptor.cFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
		                           descriptor.dwFileAttributes, NULL);

		if (!file->handle || file->handle == INVALID_HANDLE_VALUE)
			return ERROR_INTERNAL_ERROR;
	}

	/* seek to end of file */
	SetFilePointer(file->handle, 0l, NULL, FILE_END);

	/* append data to file */
	if (!WriteFile(file->handle, data, len, &written, NULL))
	{
		WLog_ERR("clipboard", "WriteFile failed!");
		CloseHandle(file->handle);
		file->handle = NULL;
		return FALSE;
	}

	file->written += written;

	UINT64 total_size = ((UINT64)descriptor.nFileSizeHigh) << 32 | (UINT64)descriptor.nFileSizeLow;
	printf("written: %ld, file size: %ld\n", file->written, total_size);

	if (file->written == total_size)
	{
		printf("finished writing file, closing.\n");
		/* close file handle */
		CloseHandle(file->handle);
		file->handle = NULL;
	}

	return TRUE;
}

pfClipboard* pf_stealer_new(CliprdrServerContext* server, CliprdrClientContext* client)
{
	pfClipboard* pfc;

	pfc = (pfClipboard*)calloc(1, sizeof(pfClipboard));
	if (!pfc)
		return NULL;

	pfc->server = server;
	pfc->client = client;
	return pfc;
}

void pf_stealer_free(pfClipboard* clipboard)
{
	size_t i;

	free(clipboard->descriptors);
	clipboard->descriptors = NULL;

	// for (i = 0; i < clipboard->nstreams; i++)
	// {
	// 	if (clipboard->stolen_files[i].handle != NULL)
	// 		CloseHandle(clipboard->stolen_files[i].handle);
	// }

	free(clipboard->streams);
	clipboard->stolen_files = NULL;
}
