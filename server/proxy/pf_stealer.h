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

#include <winpr/shell.h>
#include <winpr/wtypes.h>
#include <winpr/collections.h>

#include <freerdp/server/cliprdr.h>
#include <freerdp/client/cliprdr.h>

typedef struct file_stream fileStream;
typedef struct pf_clipboard pfClipboard;

struct file_stream
{
	ULONG m_lIndex;
	ULARGE_INTEGER m_lSize;
	ULARGE_INTEGER m_lOffset;

	BOOL received_file_size;
	BYTE* data;
	UINT64 bytes_sent;
	BOOL passed_filter;
};

struct pf_clipboard
{
	CliprdrServerContext* server;
	CliprdrClientContext* client;
	FILEDESCRIPTOR* descriptors;

	UINT32 nstreams;
	fileStream* streams;

	UINT32 last_requested_file_index;
	UINT32 lastRequestDwFlags;
	HANDLE req_fevent;
};

BOOL pf_stealer_write_file(pfClipboard* clipboard, UINT32 listIndex, const BYTE* data, UINT32 len);
BOOL pf_stealer_set_files(pfClipboard* clipboard, FILEDESCRIPTOR* descriptors, UINT count);
pfClipboard* pf_stealer_new(CliprdrServerContext* server, CliprdrClientContext* client);
void pf_stealer_free(pfClipboard* clipboard);
#endif