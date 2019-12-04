/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server
 *
 * Copyright 2019 Kobi Mizrachi <kmizrachi18@gmail.com>
 * Copyright 2019 Idan Freiberg <speidy@gmail.com>
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

#ifndef FREERDP_SERVER_PROXY_STEALER_H
#define FREERDP_SERVER_PROXY_STEALER_H

#include <winpr/wtypes.h>
#include <winpr/collections.h>

#include <freerdp/server/cliprdr.h>
#include <freerdp/client/cliprdr.h>

typedef enum clipboard_owner CLIPBOARD_OWNER;
enum clipboard_owner
{
	CLIPBOARD_OWNER_CLIENT,
	CLIPBOARD_OWNER_SERVER
};

typedef struct file_stream fileStream;
typedef struct pf_clipboard pfClipboard;

struct file_stream
{
	ULARGE_INTEGER m_lSize;
	ULARGE_INTEGER m_lOffset;

	wStream* data;
	BOOL passed_filter;
};

struct pf_clipboard
{
	CLIPBOARD_OWNER owner;

	CliprdrServerContext* server;
	CliprdrClientContext* client;

	UINT32 nstreams;
	FILEDESCRIPTOR* descriptors;
	fileStream* streams;

	UINT32 fileListFormatId;
	UINT32 requestedFileIndex;
	UINT32 requestedDwFlags;
	UINT32 clipDataId;
	UINT32 requestedFormatId;
	BOOL haveClipDataId;
};

fileStream* pf_clipboard_get_current_stream(pfClipboard* clipboard);
fileStream* pf_clipboard_get_stream(pfClipboard* clipboard, UINT32 index);

void pf_clipboard_state_update_request_info(pfClipboard* clipboard,
                                            const CLIPRDR_FILE_CONTENTS_REQUEST* request);
void pf_clipboard_state_update_format_list(pfClipboard* clipboard, const CLIPRDR_FORMAT_LIST* list);

BOOL pf_clipboard_state_update_file_list(pfClipboard* clipboard, FILEDESCRIPTOR* array, UINT count);
BOOL pf_clipboard_state_update_file_data(pfClipboard* clipboard,
                                         const CLIPRDR_FILE_CONTENTS_RESPONSE* response);

BOOL pf_clipboard_state_is_file_list_format(pfClipboard* clipboard);
BYTE* pf_clipboard_get_chunk(fileStream* stream, const CLIPRDR_FILE_CONTENTS_REQUEST* request,
                             UINT64* actual_size, BOOL* last_chunk);

pfClipboard* pf_clipboard_state_new(CliprdrServerContext* server, CliprdrClientContext* client,
                                    CLIPBOARD_OWNER owner);
void pf_clipboard_state_free(pfClipboard* clipboard);
#endif