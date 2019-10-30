/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server Session Capture
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
#include <string.h>
#include <winpr/image.h>
#include <winpr/sysinfo.h>
#include <winpr/path.h>
#include <winpr/file.h>
#include <freerdp/gdi/gdi.h>

#include "pf_context.h"
#include "modules_api.h"
#include "pf_log.h"

#define TAG PROXY_TAG("capture")

static BOOL pf_capture_create_dir_if_not_exists(const char* path)
{
	if (PathFileExistsA(path))
		return TRUE;

	return CreateDirectoryA(path, NULL);
}

static BOOL pf_capture_create_user_captures_dir(const char* base_dir, const char* username)
{
	BOOL ret;
	char* dir;

	dir = GetCombinedPath(base_dir, username);

	if (!dir)
		return FALSE;

	if (!pf_capture_create_dir_if_not_exists(dir))
		goto out;

	ret = TRUE;

out:
	free(dir);
	return ret;
}

static BOOL pf_capture_create_current_session_captures_dir(pClientContext* pc)
{
	proxyConfig* config = pc->pdata->config;
	rdpSettings* settings = pc->context.settings;
	const char* fmt = "%s/%s/%s_%02u-%02u-%" PRIu16 "_%02u-%02u-%02u-%03u";
	int rc;
	size_t size;
	SYSTEMTIME localTime;

	GetLocalTime(&localTime);

	/* create sub-directory in current user's captures directory, for the specific session. */
	rc = _snprintf(NULL, 0, fmt, config->TempFramesDirectory, settings->Username,
	               settings->ServerHostname, localTime.wDay, localTime.wMonth, localTime.wYear,
	               localTime.wHour, localTime.wMinute, localTime.wSecond, localTime.wMilliseconds);

	if (rc < 0)
		return FALSE;

	size = (size_t)rc;

	/* `pc->frames_dir` will be used by proxy client for saving frames to storage. */
	pc->frames_dir = malloc(size + 1);
	if (!pc->frames_dir)
		return FALSE;

	rc = sprintf(pc->frames_dir, fmt, config->TempFramesDirectory, settings->Username,
	             settings->ServerHostname, localTime.wDay, localTime.wMonth, localTime.wYear,
	             localTime.wHour, localTime.wMinute, localTime.wSecond, localTime.wMilliseconds);

	if (rc < 0 || (size_t)rc != size)
		goto error;

	if (!pf_capture_create_dir_if_not_exists(pc->frames_dir))
		goto error;

	return TRUE;

error:
	free(pc->frames_dir);
	return FALSE;
}

/* creates a directory to store captured session frames.
 *
 * @context: current session.
 *
 * directory path will be: base_dir/username/session-start-date.
 *
 * it is important to call this function only after the connection is fully established, as it uses
 * settings->Username and settings->ServerHostname values to create the directory. After the
 * connection established, we know that those values are valid.
 */
static BOOL pf_capture_create_session_directory(pClientContext* pc)
{
	proxyConfig* config = pc->pdata->config;
	rdpSettings* settings = pc->context.settings;

	if (!pf_capture_create_user_captures_dir(config->TempFramesDirectory, settings->Username))
		return FALSE;

	if (!pf_capture_create_current_session_captures_dir(pc))
		return FALSE;

	return TRUE;
}

static BOOL pf_capture_save_frame(pClientContext* pc, const BYTE* frame)
{
	rdpSettings* settings;
	size_t size;
	int rc;
	char* file_path = NULL;
	const char* fmt = "%s/%" PRIu64 ".bmp";

	if (!pc->frames_dir)
		return FALSE;

	rc = _snprintf(NULL, 0, fmt, pc->frames_dir, pc->frames_count);
	if (rc < 0)
		return FALSE;

	size = (size_t)rc;
	file_path = malloc(size + 1);
	if (!file_path)
		return FALSE;

	rc = sprintf(file_path, fmt, pc->frames_dir, pc->frames_count);
	if (rc < 0 || (size_t)rc != size)
		goto out;

	pc->frames_count++;

	settings = pc->context.settings;
	rc = winpr_bitmap_write(file_path, frame, settings->DesktopWidth, settings->DesktopHeight,
	                        settings->ColorDepth);

out:
	free(file_path);
	return rc;
}

/*
 * moves all frames of current session to a directory that is used for saving finished sessions
 * frames
 */
static BOOL pf_capture_move_frames_from_temp_to_full_sessions_dir(pClientContext* pc)
{
	proxyConfig* config;
	BOOL ret;
	char* dst;
	char* index;

	index = strchr(pc->frames_dir, '/');
	if (!index)
		return FALSE;

	config = pc->pdata->config;
	dst = GetCombinedPath(config->FullSessionsDirectory, index + 1);
	if (!dst)
		return FALSE;

	WLog_INFO(TAG, "moving %s to %s", pc->frames_dir, dst);
	ret = MoveFileEx(pc->frames_dir, dst, MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING);
	free(dst);
	return ret;
}

static BOOL pf_capture_session_end(moduleOperations* module, rdpContext* context)
{
	pServerContext* ps;
	pClientContext* pc;
	proxyConfig* config;
	BOOL ret = TRUE;
	char* dir;

	ps = (pServerContext*)context;
	if (!ps)
		return FALSE;

	pc = ps->pdata->pc;
	if (!pc)
		return FALSE;

	if (pc->frames_count == 0)
	{
		/* session ended but no frames were drawn (connection wasn't fully established). no need to
		 * move the frames to full session directory. */

		return TRUE;
	}

	config = ps->pdata->config;

	/* make sure a directory exists for current username in full sessions directory */
	dir = GetCombinedPath(config->FullSessionsDirectory, pc->context.settings->Username);
	if (!dir)
		return FALSE;

	if (!pf_capture_create_dir_if_not_exists(dir))
		ret = FALSE;

	free(dir);

	if (!pf_capture_move_frames_from_temp_to_full_sessions_dir(pc))
		ret = FALSE;

	return ret;
}

static BOOL pf_capture_client_end_paint(moduleOperations* module, rdpContext* context)
{
	pServerContext* ps = (pServerContext*)context;
	pClientContext* pc = ps->pdata->pc;
	rdpGdi* gdi = pc->context.gdi;

	if (gdi->suppressOutput)
		return TRUE;

	if (gdi->primary->hdc->hwnd->ninvalid < 1)
		return TRUE;

	if (!pf_capture_save_frame(pc, gdi->primary_buffer))
		WLog_ERR(TAG, "failed to save captured frame!");

	gdi->primary->hdc->hwnd->invalid->null = TRUE;
	gdi->primary->hdc->hwnd->ninvalid = 0;
	return TRUE;
}

static BOOL pf_capture_client_post_connect(moduleOperations* module, rdpContext* context)
{
	pServerContext* ps = (pServerContext*)context;
	pClientContext* pc = ps->pdata->pc;
	proxyConfig* config = ps->pdata->config;

	if (!config->DecodeGFX)
	{
		WLog_ERR(TAG, "proxy is configured to not decode GFX, can not capture session, denying connection.");
		return FALSE;
	}

	if (!pc->context.settings->SupportGraphicsPipeline)
	{
		WLog_ERR(TAG, "target does not support GFX, denying connection.");
		return FALSE;
	}

	if (!pf_capture_create_session_directory(pc))
	{
		WLog_ERR(TAG, "pf_capture_create_session_directory failed!");
		return FALSE;
	}

	WLog_INFO(TAG, "created temporary frames directory: %s", pc->frames_dir);
	return TRUE;
}

static BOOL pf_capture_server_post_connect(moduleOperations* module, rdpContext* context)
{
	pServerContext* ps = (pServerContext*)context;

	if (!ps->context.settings->SupportGraphicsPipeline)
	{
		WLog_ERR(TAG, "session capture is only supported for GFX clients, denying connection.");
		return FALSE;
	}

	return TRUE;
}

BOOL module_init(moduleOperations* module)
{
	module->ClientPostConnect = pf_capture_client_post_connect;
	module->ClientEndPaint = pf_capture_client_end_paint;
	module->ServerPostConnect = pf_capture_server_post_connect;
	module->SessionEnd = pf_capture_session_end;

	return TRUE;
}

BOOL module_exit(moduleOperations* module)
{
	return TRUE;
}
