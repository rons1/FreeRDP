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

#include "pf_cliprdr.h"
#include "pf_modules.h"
#include "pf_log.h"

#define TAG PROXY_TAG("cliprdr")
#define TEXT_FORMATS_COUNT 2

/* used for createing a fake format list response, containing only text formats */
static CLIPRDR_FORMAT g_text_formats[] = { { CF_TEXT, "\0" }, { CF_UNICODETEXT, "\0" } };

BOOL pf_server_cliprdr_init(pServerContext* ps)
{
	CliprdrServerContext* cliprdr;
	cliprdr = ps->cliprdr = cliprdr_server_context_new(ps->vcm);

	if (!cliprdr)
	{
		WLog_ERR(TAG, "cliprdr_server_context_new failed.");
		return FALSE;
	}

	cliprdr->rdpcontext = (rdpContext*)ps;

	/* enable all capabilities */
	cliprdr->useLongFormatNames = TRUE;
	cliprdr->streamFileClipEnabled = TRUE;
	cliprdr->fileClipNoFilePaths = TRUE;
	cliprdr->canLockClipData = TRUE;
	cliprdr->hasHugeFileSupport = TRUE;

	/* disable initialization sequence, for caps sync */
	cliprdr->autoInitializationSequence = FALSE;
	return TRUE;
}

static INLINE BOOL pf_cliprdr_is_text_format(UINT32 format)
{
	switch (format)
	{
		case CF_TEXT:
		case CF_UNICODETEXT:
			return TRUE;
	}

	return FALSE;
}

static INLINE void pf_cliprdr_create_text_only_format_list(CLIPRDR_FORMAT_LIST* list)
{
	list->msgFlags = CB_RESPONSE_OK;
	list->msgType = CB_FORMAT_LIST;
	list->dataLen = (4 + 1) * TEXT_FORMATS_COUNT;
	list->numFormats = TEXT_FORMATS_COUNT;
	list->formats = g_text_formats;
}

/* format data response PDU returns the copied text as a unicode buffer.
 * pf_cliprdr_is_copy_paste_valid returns TRUE if the length of the copied
 * text is valid according to the configuration value of `MaxTextLength`.
 */
static BOOL pf_cliprdr_is_copy_paste_valid(proxyConfig* config,
                                           const CLIPRDR_FORMAT_DATA_RESPONSE* pdu, UINT32 format)
{
	size_t copy_len;
	if (config->MaxTextLength == 0)
	{
		/* no size limit */
		return TRUE;
	}

	if (pdu->dataLen == 0)
	{
		/* no data */
		return FALSE;
	}

	WLog_DBG(TAG, "pf_cliprdr_is_copy_paste_valid(): checking format %" PRIu32 "", format);

	switch (format)
	{

		case CF_UNICODETEXT:
			copy_len = (pdu->dataLen / 2) - 1;
			break;
		case CF_TEXT:
			copy_len = pdu->dataLen;
			break;
		default:
			WLog_WARN(TAG, "received unknown format: %" PRIu32 ", format");
			return FALSE;
	}

	if (copy_len > config->MaxTextLength)
	{
		WLog_WARN(TAG, "text size is too large: %" PRIu32 " (max %" PRIu32 ")", copy_len,
		          config->MaxTextLength);
		return FALSE;
	}

	return TRUE;
}

/*
 * if the requested text size is too long, we need a way to return a message to the other side of
 * the connection, indicating that the copy/paste operation failed, instead of just not forwarding
 * the response (because that destroys the state of the RDPECLIP channel). This is done by sending a
 * `format_data_response` PDU with msgFlags = CB_RESPONSE_FAIL.
 */
static INLINE void pf_cliprdr_create_failed_format_data_response(CLIPRDR_FORMAT_DATA_RESPONSE* dst)
{
	dst->requestedFormatData = NULL;
	dst->dataLen = 0;
	dst->msgType = CB_FORMAT_DATA_RESPONSE;
	dst->msgFlags = CB_RESPONSE_FAIL;
}

/* server callbacks */
static UINT pf_cliprdr_ClientCapabilities(CliprdrServerContext* context,
                                          const CLIPRDR_CAPABILITIES* capabilities)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return client->ClientCapabilities(client, capabilities);
}

static UINT pf_cliprdr_TempDirectory(CliprdrServerContext* context,
                                     const CLIPRDR_TEMP_DIRECTORY* tempDirectory)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return client->TempDirectory(client, tempDirectory);
}

static UINT pf_cliprdr_ClientFormatList(CliprdrServerContext* context,
                                        const CLIPRDR_FORMAT_LIST* formatList)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);

	if (pdata->config->TextOnly)
	{
		CLIPRDR_FORMAT_LIST list;
		pf_cliprdr_create_text_only_format_list(&list);
		return client->ClientFormatList(client, &list);
	}

	/* send a format list that allows only text */
	return client->ClientFormatList(client, formatList);
}

static UINT
pf_cliprdr_ClientFormatListResponse(CliprdrServerContext* context,
                                    const CLIPRDR_FORMAT_LIST_RESPONSE* formatListResponse)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return client->ClientFormatListResponse(client, formatListResponse);
}

static UINT pf_cliprdr_ClientLockClipboardData(CliprdrServerContext* context,
                                               const CLIPRDR_LOCK_CLIPBOARD_DATA* lockClipboardData)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return client->ClientLockClipboardData(client, lockClipboardData);
}

static UINT
pf_cliprdr_ClientUnlockClipboardData(CliprdrServerContext* context,
                                     const CLIPRDR_UNLOCK_CLIPBOARD_DATA* unlockClipboardData)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return client->ClientUnlockClipboardData(client, unlockClipboardData);
}

static UINT pf_cliprdr_ClientFormatDataRequest(CliprdrServerContext* context,
                                               const CLIPRDR_FORMAT_DATA_REQUEST* formatDataRequest)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);

	if (pdata->config->TextOnly && !pf_cliprdr_is_text_format(formatDataRequest->requestedFormatId))
	{
		CLIPRDR_FORMAT_DATA_RESPONSE resp;
		pf_cliprdr_create_failed_format_data_response(&resp);
		return server->ServerFormatDataResponse(server, &resp);
	}

	return client->ClientFormatDataRequest(client, formatDataRequest);
}

static UINT
pf_cliprdr_ClientFormatDataResponse(CliprdrServerContext* context,
                                    const CLIPRDR_FORMAT_DATA_RESPONSE* formatDataResponse)
{
	proxyData* pdata = (proxyData*)context->custom;
	pClientContext* pc = pdata->pc;
	CliprdrClientContext* client = pc->cliprdr;
	FILEDESCRIPTOR* files;
	UINT32 files_count;

	WLog_VRB(TAG, __FUNCTION__);

	printf("got format %d\n", client->lastRequestedFormatId);
	if (client->lastRequestedFormatId == CB_FORMAT_TEXTURILIST)
	{
		printf("got file list\n");
		/* file list */
		UINT rc;

		rc = cliprdr_parse_file_list(formatDataResponse->requestedFormatData,
		                             formatDataResponse->dataLen, &files, &files_count);
		if (rc != NO_ERROR)
		{
			WLog_ERR(TAG, "failed to parse file list: error: 0%x", rc);
			return ERROR_INTERNAL_ERROR;
		}

		pf_stealer_set_files(pc->clipboard, files, files_count);
	}

	if (pf_cliprdr_is_text_format(client->lastRequestedFormatId))
	{
		if (!pf_cliprdr_is_copy_paste_valid(pdata->config, formatDataResponse,
		                                    client->lastRequestedFormatId))
		{
			CLIPRDR_FORMAT_DATA_RESPONSE resp;
			pf_cliprdr_create_failed_format_data_response(&resp);
			return client->ClientFormatDataResponse(client, &resp);
		}
	}

	return client->ClientFormatDataResponse(client, formatDataResponse);
}

static UINT
pf_cliprdr_ClientFileContentsRequest(CliprdrServerContext* context,
                                     const CLIPRDR_FILE_CONTENTS_REQUEST* fileContentsRequest)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);

	if (pdata->config->TextOnly)
		return CHANNEL_RC_OK;

	return client->ClientFileContentsRequest(client, fileContentsRequest);
}

UINT cliprdr_send_request_filecontents(pfClipboard* clipboard, UINT32 streamId, ULONG index,
                                       UINT32 flag, DWORD positionhigh, DWORD positionlow,
                                       ULONG nreq)
{
	UINT rc;
	CLIPRDR_FILE_CONTENTS_REQUEST fileContentsRequest = { 0 };

	if (!clipboard || !clipboard->server || !clipboard->server->ClientFileContentsRequest)
		return ERROR_INTERNAL_ERROR;

	fileContentsRequest.streamId = streamId;
	fileContentsRequest.listIndex = index;
	fileContentsRequest.dwFlags = flag;
	fileContentsRequest.nPositionLow = positionlow;
	fileContentsRequest.nPositionHigh = positionhigh;
	fileContentsRequest.cbRequested = nreq;
	fileContentsRequest.clipDataId = 0;
	fileContentsRequest.msgFlags = CB_RESPONSE_OK;
	fileContentsRequest.msgType = CB_FILECONTENTS_REQUEST;
	rc = clipboard->server->ServerFileContentsRequest(clipboard->server, &fileContentsRequest);

	return rc;
}

UINT cliprdr_send_response_filecontents(pfClipboard* clipboard, UINT32 streamId, ULONG index,
                                        BYTE* data, ULONG nreq, UINT16 flags)
{
	CLIPRDR_FILE_CONTENTS_RESPONSE resp = { 0 };

	if (!clipboard || !clipboard->client || !clipboard->client->ClientFileContentsResponse)
		return ERROR_INTERNAL_ERROR;

	resp.streamId = streamId;
	resp.cbRequested = nreq;
	resp.msgFlags = flags;
	resp.msgType = CB_FILECONTENTS_RESPONSE;
	resp.requestedData = data;
	return clipboard->client->ClientFileContentsResponse(clipboard->client, &resp);
}

static UINT
pf_cliprdr_ClientFileContentsResponse(CliprdrServerContext* context,
                                      const CLIPRDR_FILE_CONTENTS_RESPONSE* fileContentsResponse)
{
	UINT32 index;
	FILEDESCRIPTOR file;
	proxyData* pdata = (proxyData*)context->custom;
	pfClipboard* clipboard = pdata->pc->clipboard;
	// CliprdrClientContext* client = pdata->pc->cliprdr;
	fileStream* stream;
	WLog_VRB(TAG, __FUNCTION__);

	if (pdata->config->TextOnly)
		return CHANNEL_RC_OK;

	index = pdata->pc->last_requested_file_index;

	if (index >= clipboard->nstreams)
		return ERROR_BAD_ARGUMENTS;

	stream = &clipboard->streams[index];

	file = clipboard->descriptors[index];
	stream->m_lSize.LowPart = file.nFileSizeLow;
	stream->m_lSize.HighPart = file.nFileSizeHigh;
	UINT64 total_size = ((UINT64)file.nFileSizeHigh) << 32 | (UINT64)file.nFileSizeLow;

	if (!stream->received_file_size)
	{
		if (fileContentsResponse->cbRequested != 8)
		{
			WLog_ERR(TAG,
			         "expected file size, fileContentsResponse->cbRequested must be equal to 8");
			return ERROR_INVALID_DATA;
		}

		stream->received_file_size = TRUE;
	}
	else
	{
		if (!stream->data)
		{
			stream->data = malloc(total_size);
			if (!stream->data)
				WLog_ERR(TAG, "failed to allocate memory for file");
		}

		// copy the data to memory
		CopyMemory(stream->data + stream->m_lOffset.LowPart, fileContentsResponse->requestedData,
		           fileContentsResponse->cbRequested);

		// update offset
		stream->m_lOffset.LowPart += fileContentsResponse->cbRequested;

		if (stream->m_lOffset.LowPart == total_size)
		{
			/* received all file data, run filter */
			proxyFileCopyEventInfo event;
			event.data = stream->data;
			event.data_len = stream->m_lSize.LowPart;
			event.client_to_server = TRUE;
			printf("received full file, running external filters.");
			stream->passed_filter =
			    pf_modules_run_filter(FILTER_TYPE_FILE_COPY, (rdpContext*)pdata->ps, &event);
			cliprdr_send_response_filecontents(pdata->pc->clipboard, fileContentsResponse->streamId,
			                                   index, (BYTE*)&total_size, 8, CB_RESPONSE_OK);
			return CHANNEL_RC_OK;
		}
	}

	/* got file size, now request first chunk of data */
	DWORD chunk_size = 262144;
	if (chunk_size > total_size)
		chunk_size = total_size;

	/* request data from client */
	cliprdr_send_request_filecontents(clipboard, fileContentsResponse->streamId, index,
	                                  FILECONTENTS_RANGE, stream->m_lOffset.HighPart,
	                                  stream->m_lOffset.LowPart, chunk_size);
	return CHANNEL_RC_OK;

	// return client->ClientFileContentsResponse(client, fileContentsResponse);
}

/* client callbacks */

static UINT pf_cliprdr_ServerCapabilities(CliprdrClientContext* context,
                                          const CLIPRDR_CAPABILITIES* capabilities)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return server->ServerCapabilities(server, capabilities);
}

static UINT pf_cliprdr_MonitorReady(CliprdrClientContext* context,
                                    const CLIPRDR_MONITOR_READY* monitorReady)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return server->MonitorReady(server, monitorReady);
}

static UINT pf_cliprdr_ServerFormatList(CliprdrClientContext* context,
                                        const CLIPRDR_FORMAT_LIST* formatList)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);

	if (pdata->config->TextOnly)
	{
		CLIPRDR_FORMAT_LIST list = { 0 };
		pf_cliprdr_create_text_only_format_list(&list);
		return server->ServerFormatList(server, &list);
	}

	return server->ServerFormatList(server, formatList);
}

static UINT
pf_cliprdr_ServerFormatListResponse(CliprdrClientContext* context,
                                    const CLIPRDR_FORMAT_LIST_RESPONSE* formatListResponse)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return server->ServerFormatListResponse(server, formatListResponse);
}

static UINT pf_cliprdr_ServerLockClipboardData(CliprdrClientContext* context,
                                               const CLIPRDR_LOCK_CLIPBOARD_DATA* lockClipboardData)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return server->ServerLockClipboardData(server, lockClipboardData);
}

static UINT
pf_cliprdr_ServerUnlockClipboardData(CliprdrClientContext* context,
                                     const CLIPRDR_UNLOCK_CLIPBOARD_DATA* unlockClipboardData)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);
	return server->ServerUnlockClipboardData(server, unlockClipboardData);
}

static UINT pf_cliprdr_ServerFormatDataRequest(CliprdrClientContext* context,
                                               const CLIPRDR_FORMAT_DATA_REQUEST* formatDataRequest)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	CliprdrClientContext* client = pdata->pc->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);

	if (pdata->config->TextOnly && !pf_cliprdr_is_text_format(formatDataRequest->requestedFormatId))
	{
		/* proxy's client needs to return a failed response directly to the client
		 */
		CLIPRDR_FORMAT_DATA_RESPONSE resp;
		pf_cliprdr_create_failed_format_data_response(&resp);
		return client->ClientFormatDataResponse(client, &resp);
	}

	return server->ServerFormatDataRequest(server, formatDataRequest);
}

static UINT
pf_cliprdr_ServerFormatDataResponse(CliprdrClientContext* context,
                                    const CLIPRDR_FORMAT_DATA_RESPONSE* formatDataResponse)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);

	if (pf_cliprdr_is_text_format(server->lastRequestedFormatId))
	{
		if (!pf_cliprdr_is_copy_paste_valid(pdata->config, formatDataResponse,
		                                    server->lastRequestedFormatId))
		{
			CLIPRDR_FORMAT_DATA_RESPONSE resp;
			pf_cliprdr_create_failed_format_data_response(&resp);
			return server->ServerFormatDataResponse(server, &resp);
		}
	}

	return server->ServerFormatDataResponse(server, formatDataResponse);
}

static UINT
pf_cliprdr_ServerFileContentsRequest(CliprdrClientContext* context,
                                     const CLIPRDR_FILE_CONTENTS_REQUEST* fileContentsRequest)
{
	UINT rc = CHANNEL_RC_OK;
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	pfClipboard* clipboard = pdata->pc->clipboard;
	fileStream* current;
	WLog_VRB(TAG, __FUNCTION__);

	pdata->pc->lastRequestDwFlags = fileContentsRequest->dwFlags;
	pdata->pc->last_requested_file_index = fileContentsRequest->listIndex;

	if (pdata->config->TextOnly)
		return CHANNEL_RC_OK;

	if (fileContentsRequest->listIndex >= clipboard->nstreams)
		return ERROR_BAD_ARGUMENTS;

	/*
	 * proxy's client received a file contents request.
	 * if dwFlags is equal to FILECONTENTS_SIZE, proxy should just proxy the request and send the
	 * response back. if dwFlags is equal to FILECONTENTS_RANGE, proxy should send the partial data
	 * back to the remote server.
	 */
	if (fileContentsRequest->dwFlags == FILECONTENTS_SIZE)
		return server->ServerFileContentsRequest(server, fileContentsRequest);

	current = &clipboard->streams[fileContentsRequest->listIndex];
	if (current->passed_filter == FALSE)
	{
		/* free data */
		free(current->data);
		current->data = NULL;

		/* file did not pass filter */
		return cliprdr_send_response_filecontents(clipboard, fileContentsRequest->streamId,
		                                          fileContentsRequest->listIndex, NULL, 0,
		                                          CB_RESPONSE_FAIL);
	}

	UINT64 n = fileContentsRequest->cbRequested;
	if (n > current->m_lSize.LowPart)
		n = current->m_lSize.LowPart;

	if (fileContentsRequest->nPositionLow + n > current->m_lSize.LowPart)
		n = current->m_lSize.LowPart - fileContentsRequest->nPositionLow;

	printf("target server requested max %d bytes\n", fileContentsRequest->cbRequested);
	printf("sending him %ld bytes\n", n);
	current->bytes_sent += n;

	rc = cliprdr_send_response_filecontents(
	    clipboard, fileContentsRequest->streamId, fileContentsRequest->listIndex,
	    current->data + fileContentsRequest->nPositionLow, n, CB_RESPONSE_OK);

	if (current->bytes_sent == current->m_lSize.LowPart)
	{
		/* free data */
		free(current->data);
		current->data = NULL;
	}

	return rc;
	// return server->ServerFileContentsRequest(server, fileContentsRequest);
}

static UINT
pf_cliprdr_ServerFileContentsResponse(CliprdrClientContext* context,
                                      const CLIPRDR_FILE_CONTENTS_RESPONSE* fileContentsResponse)
{
	proxyData* pdata = (proxyData*)context->custom;
	CliprdrServerContext* server = pdata->ps->cliprdr;
	WLog_VRB(TAG, __FUNCTION__);

	if (pdata->config->TextOnly)
		return CHANNEL_RC_OK;

	return server->ServerFileContentsResponse(server, fileContentsResponse);
}

void pf_cliprdr_register_callbacks(CliprdrClientContext* cliprdr_client,
                                   CliprdrServerContext* cliprdr_server, proxyData* pdata)
{
	/* Set server and client side references to proxy data */
	cliprdr_server->custom = (void*)pdata;
	cliprdr_client->custom = (void*)pdata;
	/* Set server callbacks */
	cliprdr_server->ClientCapabilities = pf_cliprdr_ClientCapabilities;
	cliprdr_server->TempDirectory = pf_cliprdr_TempDirectory;
	cliprdr_server->ClientFormatList = pf_cliprdr_ClientFormatList;
	cliprdr_server->ClientFormatListResponse = pf_cliprdr_ClientFormatListResponse;
	cliprdr_server->ClientLockClipboardData = pf_cliprdr_ClientLockClipboardData;
	cliprdr_server->ClientUnlockClipboardData = pf_cliprdr_ClientUnlockClipboardData;
	cliprdr_server->ClientFormatDataRequest = pf_cliprdr_ClientFormatDataRequest;
	cliprdr_server->ClientFormatDataResponse = pf_cliprdr_ClientFormatDataResponse;
	cliprdr_server->ClientFileContentsRequest = pf_cliprdr_ClientFileContentsRequest;
	cliprdr_server->ClientFileContentsResponse = pf_cliprdr_ClientFileContentsResponse;
	/* Set client callbacks */
	cliprdr_client->ServerCapabilities = pf_cliprdr_ServerCapabilities;
	cliprdr_client->MonitorReady = pf_cliprdr_MonitorReady;
	cliprdr_client->ServerFormatList = pf_cliprdr_ServerFormatList;
	cliprdr_client->ServerFormatListResponse = pf_cliprdr_ServerFormatListResponse;
	cliprdr_client->ServerLockClipboardData = pf_cliprdr_ServerLockClipboardData;
	cliprdr_client->ServerUnlockClipboardData = pf_cliprdr_ServerUnlockClipboardData;
	cliprdr_client->ServerFormatDataRequest = pf_cliprdr_ServerFormatDataRequest;
	cliprdr_client->ServerFormatDataResponse = pf_cliprdr_ServerFormatDataResponse;
	cliprdr_client->ServerFileContentsRequest = pf_cliprdr_ServerFileContentsRequest;
	cliprdr_client->ServerFileContentsResponse = pf_cliprdr_ServerFileContentsResponse;
}
