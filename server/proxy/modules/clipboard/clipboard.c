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

static BOOL clipboard_file_metadata_received(moduleOperations* module, rdpContext* context,
                                             void* param)
{
	proxyPreFileCopyEventInfo* ev = (proxyPreFileCopyEventInfo*)param;

	/* do not allow sending files over 5MB */
	WLog_INFO(TAG, "filter: got data len=%ld", ev->total_size);
	if (ev->total_size >= 15 * 1024 * 1024)
		return FALSE;

	return TRUE;
}

static BOOL clipboard_file_data_received(moduleOperations* module, rdpContext* context, void* param)
{
	proxyFileCopyEventInfo* ev = (proxyFileCopyEventInfo*)param;
	winpr_HexDump(TAG, WLOG_DEBUG, ev->data, ev->data_len);
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
