/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server
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

#include <stdio.h>
#include <winpr/print.h>

#include "modules_api.h"
#include "pf_log.h"

#define TAG MODULE_TAG("clipboard_filter")

static UINT64 file_index = 1;

static BOOL clipboard_file_metadata_received(moduleOperations* module, rdpContext* context,
                                             void* param)
{
	int rc;
	size_t size;
	proxyPreFileCopyEventInfo* ev = (proxyPreFileCopyEventInfo*)param;

	if (ev == NULL)
		return FALSE;

	char* new_name;

	rc = snprintf(NULL, 0, "freerdp-proxy-file_%ld.txt", file_index);
	if (rc < 0)
		return FALSE;

	size = (size_t)rc;
	new_name = malloc(size + 1);
	rc = sprintf(new_name, "freerdp-proxy-file_%ld.txt", file_index);
	if (rc < 0 || (size_t)rc != size)
		return FALSE;

	file_index++;
	ev->new_name = new_name;
	return TRUE;
}

static BOOL clipboard_file_data_received(moduleOperations* module, rdpContext* context, void* param)
{
	proxyFileCopyEventInfo* ev = (proxyFileCopyEventInfo*)param;
	WLog_INFO(TAG, "module got file: client to server=%d\n", ev->client_to_server);

	char* new_data = _strdup("hello, this file was modified by freerdp-proxy.");
	ev->new_data = (BYTE*)new_data;
	ev->new_data_len = strlen(new_data);
	return TRUE;
}

BOOL module_init(moduleOperations* module)
{
	module->ClipboardFileMetadata = clipboard_file_metadata_received;
	module->ClipboardFileData = clipboard_file_data_received;
	return TRUE;
}

BOOL module_exit(moduleOperations* module)
{
	return TRUE;
}
