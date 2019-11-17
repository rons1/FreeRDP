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

#include "modules_api.h"
#include "pf_log.h"

#define TAG PROXY_TAG("modules.clipboard")

static BOOL clipboard_filter_file_copy(moduleOperations* module, rdpContext* context, void* param)
{
	proxyFileCopyEventInfo* ev = (proxyFileCopyEventInfo*)param;
	// winpr_HexDump(TAG, WLOG_INFO, ev->data, ev->data_len);

	/* do not allow sending files over 5MB */
	printf("filter: got data len=%d\n", ev->data_len);
	if (ev->data_len >= 5 * 1024 * 1024)
		return FALSE;

	return TRUE;
}

BOOL module_init(moduleOperations* module)
{
	module->ClipboardFileCopy = clipboard_filter_file_copy;
	return TRUE;
}

BOOL module_exit(moduleOperations* module)
{
	printf("bye bye\n");

	return TRUE;
}
