/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Clipboard State
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

#include "pf_log.h"
#include "clipboard_state.h"

#define TAG PROXY_TAG("clipboard.state")

static BOOL pf_clipboard_state_update_file_list(pfClipboard* clipboard, FILEDESCRIPTOR* descriptors,
                                                UINT count)
{
	size_t i;
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

	/* initialize streams */
	for (i = 0; i < clipboard->nstreams; i++)
	{
		FILEDESCRIPTOR file = clipboard->descriptors[i];
		fileStream* stream = &clipboard->streams[i];

		stream->m_lSize.u.LowPart = file.nFileSizeLow;
		stream->m_lSize.u.HighPart = file.nFileSizeHigh;
		stream->data = Stream_New(NULL, stream->m_lSize.QuadPart);

		if (!stream->data)
		{
			WLog_ERR(TAG, "failed to allocate memory for file data");
			return FALSE;
		}
	}

	return TRUE;
}

fileStream* pf_clipboard_get_current_stream(pfClipboard* clipboard)
{
	if (clipboard->requestedFileIndex >= clipboard->nstreams)
		return NULL;

	return &clipboard->streams[clipboard->requestedFileIndex];
}

fileStream* pf_clipboard_get_stream(pfClipboard* clipboard, UINT32 index)
{
	if (index >= clipboard->nstreams)
		return NULL;

	return &clipboard->streams[index];
}

static BOOL pf_clipboard_state_update_format_list(pfClipboard* clipboard,
                                                  const CLIPRDR_FORMAT_LIST* formatList)
{
	size_t i;

	for (i = 0; i < formatList->numFormats; i++)
	{
		if (NULL == formatList->formats[i].formatName)
			continue;

		if (strcmp("FileGroupDescriptorW", formatList->formats[i].formatName) == 0)
		{
			clipboard->fileListFormatId = formatList->formats[i].formatId;
			WLog_DBG(TAG, "file list format id: 0x%x", clipboard->fileListFormatId);
			return TRUE;
		}
	}

	return TRUE;
}

static BOOL pf_clipboard_state_update_request_info(pfClipboard* clipboard,
                                                   const CLIPRDR_FILE_CONTENTS_REQUEST* request)
{
	clipboard->requestedFileIndex = request->listIndex;
	clipboard->requestedDwFlags = request->dwFlags;
	clipboard->haveClipDataId = request->haveClipDataId;

	if (clipboard->haveClipDataId)
		clipboard->clipDataId = request->clipDataId;
	else
		clipboard->clipDataId = 0;

	return TRUE;
}

static BOOL pf_clipboard_state_update_file_data(pfClipboard* clipboard,
                                                const CLIPRDR_FILE_CONTENTS_RESPONSE* response)
{
	fileStream* stream = pf_clipboard_get_current_stream(clipboard);

	/* no need to do anything if this is a response for FILECONTENTS_SIZE request */
	if (clipboard->requestedDwFlags == FILECONTENTS_SIZE)
		return TRUE;

	if (!stream)
	{
		WLog_ERR(TAG, "file list is invalid");
		return FALSE;
	}

	if (response->cbRequested > Stream_GetRemainingLength(stream->data))
	{
		WLog_ERR(TAG, "received more file data than expected");
		// TODO: free this stream
		return FALSE;
	}

	/* copy data to memory buffer */
	Stream_Write(stream->data, response->requestedData, response->cbRequested);

	/* update offset */
	stream->m_lOffset.QuadPart += response->cbRequested;
	return TRUE;
}

BOOL pf_clipboard_state_is_file_list_format(pfClipboard* clipboard)
{
	return clipboard->fileListFormatId == clipboard->requestedFormatId;
}

pfClipboard* pf_clipboard_state_new(CliprdrServerContext* server, CliprdrClientContext* client,
                                    CLIPBOARD_OWNER owner)
{
	pfClipboard* pfc;

	pfc = (pfClipboard*)calloc(1, sizeof(pfClipboard));
	if (!pfc)
		return NULL;

	pfc->owner = owner;

	pfc->server = server;
	pfc->client = client;

	pfc->OnReceivedFileContentsRequest = pf_clipboard_state_update_request_info;
	pfc->OnReceivedFileContentsResponse = pf_clipboard_state_update_file_data;
	pfc->OnReceivedFileList = pf_clipboard_state_update_file_list;
	pfc->OnReceivedFormatList = pf_clipboard_state_update_format_list;
	return pfc;
}

BYTE* pf_clipboard_get_chunk(fileStream* stream, const CLIPRDR_FILE_CONTENTS_REQUEST* request,
                             UINT32* actual_size, BOOL* last_chunk)
{
	UINT64 file_size = stream->m_lSize.QuadPart;
	UINT32 nreq = request->cbRequested;
	UINT32 actual_chunk_size;
	ULARGE_INTEGER requested_offset;

	requested_offset.u.LowPart = request->nPositionLow;
	requested_offset.u.HighPart = request->nPositionHigh;

	/* invalid offset */
	if (requested_offset.QuadPart >= file_size)
		return NULL;

	Stream_SetPosition(stream->data, requested_offset.QuadPart);

	/*
	 * if the number of requested bytes is bigger than the size of the remaiming data, the chunk
	 * size should be the size of the remamiming data.
	 */

	actual_chunk_size = nreq;
	if (nreq >= Stream_GetRemainingLength(stream->data)) /* send only what's left */
		actual_chunk_size = file_size - requested_offset.QuadPart;

	*actual_size = actual_chunk_size;
	*last_chunk = (requested_offset.QuadPart + actual_chunk_size == file_size);

	return Stream_Pointer(stream->data);
}

void pf_clipboard_stream_free(pfClipboard* clipboard, UINT32 listIndex)
{
	fileStream* stream = pf_clipboard_get_stream(clipboard, listIndex);
	if (!stream)
		return;

	Stream_Free(stream->data, TRUE);
	stream->data = NULL;
}

void pf_clipboard_state_free(pfClipboard* clipboard)
{
	size_t i;

	free(clipboard->descriptors);
	clipboard->descriptors = NULL;

	for (i = 0; i < clipboard->nstreams; i++)
	{
		if (clipboard->streams[i].data)
			Stream_Free(clipboard->streams[i].data, TRUE);
	}

	free(clipboard->streams);
	clipboard->streams = NULL;
}
