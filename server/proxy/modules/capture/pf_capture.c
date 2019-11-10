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

#include <winpr/image.h>
#include <freerdp/gdi/gdi.h>
#include <winpr/winsock.h>

#include "pf_context.h"
#include "modules_api.h"
#include "pf_log.h"

#define HEADER_SIZE 6
#define SESSION_INFO_PDU_BASE_SIZE 6
#define SESSION_END_PDU_BASE_SIZE 0
#define CAPTURED_FRAME_PDU_BASE_SIZE 0

/* message types */
#define MESSAGE_TYPE_SESSION_INFO 1
#define MESSAGE_TYPE_CAPTURED_FRAME 2
#define MESSAGE_TYPE_SESSION_END 3

#define TAG PROXY_TAG("capture")

static int capture_module_init_socket()
{
	int status;
	int sockfd;
	struct sockaddr_in addr = { 0 };
	sockfd = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sockfd == -1)
		return -1;

	addr.sin_family = AF_INET;   /* host byte order */
	addr.sin_port = htons(8889); /* short, network byte order */
	inet_pton(AF_INET, "127.0.0.1", &(addr.sin_addr));

	// addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	status = _connect(sockfd, (const struct sockaddr*)&addr, sizeof(addr));
	if (status < 0)
	{
		close(sockfd);
		return -1;
	}

	return sockfd;
}

static wStream* pf_capture_packet_new(UINT32 payload_size, UINT16 type)
{
	wStream* stream = Stream_New(NULL, HEADER_SIZE + payload_size);
	if (!stream)
		return NULL;

	Stream_Write_UINT32(stream, payload_size);
	Stream_Write_UINT16(stream, type);
	return stream;
}

static BOOL pf_capture_send_packet(SOCKET sockfd, wStream* packet)
{
	int nsent;
	size_t len;
	size_t chunk_len;
	BYTE* buffer;
	BOOL result = FALSE;

	if (!packet)
		return FALSE;

	buffer = Stream_Buffer(packet);
	len = Stream_Capacity(packet);

	while (len > 0)
	{
		chunk_len = len > 8092 ? 8092 : len;
		nsent = _send(sockfd, (const char*)buffer, chunk_len, 0);
		if (nsent == -1)
		{
			int errorn = WSAGetLastError();
			printf("error: %d\n", errorn);
			goto error;
		}

		buffer += nsent;
		len -= nsent;
	}

	result = TRUE;
error:
	Stream_Free(packet, TRUE);
	return result;
}

static BOOL pf_capture_session_end(moduleOperations* module, rdpContext* context)
{
	pServerContext* ps;
	pClientContext* pc;
	SOCKET socket;
	BOOL ret;

	ps = (pServerContext*)context;
	if (!ps)
		return FALSE;

	pc = ps->pdata->pc;
	if (!pc)
		return FALSE;

	socket = (SOCKET)module->GetSessionData(module, context);

	wStream* s = pf_capture_packet_new(SESSION_END_PDU_BASE_SIZE, MESSAGE_TYPE_SESSION_END);
	ret = pf_capture_send_packet(socket, s);
	closesocket(socket);
	return ret;
}

static BOOL pf_capture_send_frame_to_service(pClientContext* pc, SOCKET socket, const BYTE* buffer)
{
	BOOL ret = FALSE;
	UINT32 img_size;
	rdpSettings* settings = pc->context.settings;
	wStream* s;
	wStream* image_header = winpr_bitmap_construct_header(
	    buffer, settings->DesktopWidth, settings->DesktopHeight, settings->ColorDepth, &img_size);

	s = pf_capture_packet_new(CAPTURED_FRAME_PDU_BASE_SIZE + Stream_Length(image_header) + img_size,
	                          MESSAGE_TYPE_CAPTURED_FRAME);

	Stream_Write(s, Stream_Buffer(image_header), Stream_Length(image_header)); /* image header */
	Stream_Write(s, buffer, img_size);                                         /* image data */

	ret = pf_capture_send_packet(socket, s);
	Stream_Free(image_header, TRUE);
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

	SOCKET socket = (SOCKET)module->GetSessionData(module, context);
	if (!pf_capture_send_frame_to_service(pc, socket, gdi->primary_buffer))
	{
		WLog_ERR(TAG, "pf_capture_send_frame_to_service failed!");
		return FALSE;
	}

	gdi->primary->hdc->hwnd->invalid->null = TRUE;
	gdi->primary->hdc->hwnd->ninvalid = 0;
	return TRUE;
}

static BOOL pf_capture_client_post_connect(moduleOperations* module, rdpContext* context)
{
	SOCKET socket;
	pServerContext* ps = (pServerContext*)context;
	pClientContext* pc = ps->pdata->pc;
	wStream* s;
	UINT16 username_length;

	if (!pc->context.settings->SupportGraphicsPipeline)
	{
		WLog_ERR(TAG, "target does not support GFX, denying connection.");
		return FALSE;
	}

	socket = capture_module_init_socket();
	if (socket == -1)
	{
		WLog_ERR(TAG, "failed to establish a connection");
		return FALSE;
	}

	// save socket descriptor for current session.
	module->SetSessionData(module, context, (void*)socket);

	username_length = strlen(pc->context.settings->Username);
	s = pf_capture_packet_new(SESSION_INFO_PDU_BASE_SIZE + username_length,
	                          MESSAGE_TYPE_SESSION_INFO);

	Stream_Write_UINT16(s, username_length); /* username length (2 bytes) */
	Stream_Write(s, pc->context.settings->Username,
	             username_length); /* username (username_length bytes) */
	Stream_Write_UINT16(s, pc->context.settings->DesktopWidth);  /* desktop width (2 bytes) */
	Stream_Write_UINT16(s, pc->context.settings->DesktopHeight); /* desktop height (2 bytes) */
	return pf_capture_send_packet(socket, s);
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
