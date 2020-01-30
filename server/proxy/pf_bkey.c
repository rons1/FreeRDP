/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server BioKey channel
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

#include <freerdp/client/passthrough.h>
#include <freerdp/server/passthrough.h>

#include <winpr/synch.h>
#include <winpr/print.h>
#include <winpr/error.h>

#include "pf_bkey.h"
#include "pf_log.h"

#define TAG PROXY_TAG("bkey")

#define BKEY_SERVER_HEADER_LEN 0x80
#define BKEY_CLIENT_HEADER_LEN (BKEY_SERVER_HEADER_LEN + 4)

/* message types */
#define BKEY_CAMERA_START_REQUEST 0x1
#define BKEY_CAMERA_START_RESPONSE 0x2
#define BKEY_CAMERA_STOP_REQUEST 0x3
#define BKEY_CAMERA_STOP_RESPONSE 0x4
#define BKEY_DETECT_FINGER_REQUEST 0x7
#define BKEY_DETECT_FINGER_RESPONSE 0x8

#define NR_STATE 4

enum bkey_state
{
	STATE_FIRST_SERVER_PDU,
	STATE_FIRST_CLIENT_PDU,
	STATE_DETECT_FINGER_REQUEST,
	STATE_DETECT_FINGER_RESPONSE,
};

#define STATE_OK STATE_DETECT_FINGER_RESPONSE + 1

/* static variable holding the current verification state */
static wHashTable* g_current_states = NULL;

/* state handlers */
typedef BOOL (*state_handler)(wStream*, enum bkey_state*);

static BOOL bkey_verify_first_server_pdu(wStream*, enum bkey_state*);
static BOOL bkey_verify_first_client_pdu(wStream*, enum bkey_state*);
static BOOL bkey_verify_detect_finger_request(wStream*, enum bkey_state*);
static BOOL bkey_verify_detect_finger_response(wStream*, enum bkey_state*);

static state_handler state_handlers[NR_STATE] = { bkey_verify_first_server_pdu,
	                                              bkey_verify_first_client_pdu,
	                                              bkey_verify_detect_finger_request,
	                                              bkey_verify_detect_finger_response };

static BOOL pf_bkey_check_build_info(wStream* input)
{
	UINT32 major;
	UINT32 minor;

	Stream_Read_UINT32_BE(input, major);
	Stream_Read_UINT32_BE(input, minor);

	if (major != 0x6 || minor != 0x6)
	{
		WLog_ERR(TAG, "got wrong build info");
		return FALSE;
	}

	return TRUE;
}

static BOOL bkey_validate_message_type(wStream* input, UINT32 expected_message_type)
{
	UINT32 message_type;

	Stream_Read_UINT32_BE(input, message_type); /* 4 bytes - message type */

	if (message_type != expected_message_type)
	{
		WLog_ERR(TAG, "bkey_verify_client_pdu: expected message type 0x%x, got 0x%x",
		         expected_message_type, message_type);
		return FALSE;
	}

	return TRUE;
}

static BOOL bkey_verify_server_pdu(wStream* input, UINT32 expected_message_type)
{
	if (Stream_GetRemainingLength(input) < 148)
		return FALSE;

	if (!pf_bkey_check_build_info(input))
		return FALSE;

	Stream_SetPosition(input, BKEY_SERVER_HEADER_LEN); /* skip header */
	return bkey_validate_message_type(input, expected_message_type);
}

/*
 * reads header, verifies stream length, build info and message type.
 * when returns, stream position is after header and message type (current payload).
 */
static BOOL bkey_verify_client_pdu(wStream* input, UINT32 expected_message_type)
{
	UINT32 data_len;

	if (Stream_GetRemainingLength(input) < 4)
		return FALSE;

	/* first 4 bytes is data length */
	Stream_Read_UINT32_BE(input, data_len);

	if (Stream_Capacity(input) - 4 != data_len)
	{
		WLog_ERR(TAG, "bkey_verify_client_pdu: data len is invalid!");
		return FALSE;
	}

	if (!pf_bkey_check_build_info(input))
		return FALSE;

	Stream_SetPosition(input, BKEY_CLIENT_HEADER_LEN); /* skip header */
	return bkey_validate_message_type(input, expected_message_type);
}

static BOOL bkey_verify_first_server_pdu(wStream* input, enum bkey_state* next)
{
	if (!bkey_verify_server_pdu(input, BKEY_CAMERA_START_REQUEST))
		return FALSE;

	return TRUE;
}

static BOOL bkey_verify_first_client_pdu(wStream* input, enum bkey_state* next)
{
	if (!bkey_verify_client_pdu(input, BKEY_CAMERA_START_RESPONSE))
		return FALSE;

	return TRUE;
}

static BOOL bkey_verify_detect_finger_request(wStream* input, enum bkey_state* next)
{
	if (!bkey_verify_server_pdu(input, BKEY_DETECT_FINGER_REQUEST))
		return FALSE;

	return TRUE;
}

static BOOL bkey_verify_detect_finger_response(wStream* input, enum bkey_state* next)
{
	UINT32 is_finger_pressed;

	if (!bkey_verify_client_pdu(input, BKEY_DETECT_FINGER_RESPONSE))
		return FALSE;

	Stream_SafeSeek(input, 4);
	Stream_Read_UINT32_BE(input, is_finger_pressed); /* 4 bytes - is finger pressed */

	if (is_finger_pressed == 0)
	{
		/* finger is not pressed yet, go back to detect request state */
		*next = STATE_DETECT_FINGER_REQUEST;
	}

	return TRUE;
}

static BOOL pf_bkey_check_current_state(proxyData* pdata, wStream* input)
{
	enum bkey_state current_state;
	enum bkey_state next;

	current_state = (enum bkey_state)HashTable_GetItemValue(g_current_states, pdata);
	next = current_state + 1;

	WLog_DBG(TAG, "pf_bkey_check_current_state: current state: %d", current_state);
	if (current_state == STATE_OK)
		return TRUE;

	state_handler handler = state_handlers[current_state];
	if (!handler(input, &next))
	{
		WLog_ERR(TAG, "handler %d failed!", current_state);
		return FALSE;
	}

	/* proceed to next state */
	HashTable_SetItemValue(g_current_states, pdata, (void*)next);
	return TRUE;
}

static UINT pf_bkey_data_received_from_client(PassthroughServerContext* context, const BYTE* data,
                                              UINT32 len)
{
	wStream s;
	proxyData* pdata = (proxyData*)context->custom;
	PassthroughClientContext* client = (PassthroughClientContext*)pdata->pc->bkey;

	WLog_DBG(TAG, "received data from client, len: %d", len);
	winpr_HexDump(TAG, WLOG_DEBUG, data, len);

	Stream_StaticInit(&s, (BYTE*)data, len);

	if (!pf_bkey_check_current_state(pdata, &s))
	{
		WLog_WARN(TAG, "bkey_recv_from_client: pf_bkey_check_current_state failed!");
		return ERROR_INTERNAL_ERROR;
	}

	return client->SendData(client, data, len);
}

static UINT pf_bkey_data_received_from_server(PassthroughClientContext* context, const BYTE* data,
                                              UINT32 len)
{
	wStream s;
	proxyData* pdata = (proxyData*)context->custom;
	PassthroughServerContext* server = (PassthroughServerContext*)pdata->ps->bkey;

	WLog_DBG(TAG, "received data from server, len: %d", len);
	winpr_HexDump(TAG, WLOG_DEBUG, data, len);

	Stream_StaticInit(&s, (BYTE*)data, len);

	if (!pf_bkey_check_current_state(pdata, &s))
	{
		WLog_WARN(TAG, "bkey_recv_from_server: pf_bkey_check_current_state failed!");
		return ERROR_INTERNAL_ERROR;
	}

	return server->SendData(server, data, len);
}

BOOL pf_bkey_state_machine_init()
{
	g_current_states = HashTable_New(TRUE);
	if (!g_current_states)
		return FALSE;

	return TRUE;
}

void pf_bkey_state_machine_uninit()
{
	HashTable_Free(g_current_states);
}

BOOL pf_server_bkey_init(pServerContext* ps)
{
	PassthroughServerContext* bkey;
	bkey = ps->bkey = passthrough_server_context_new(ps->vcm, BKEY_CHANNEL_NAME);

	if (!bkey)
	{
		return FALSE;
	}

	bkey->rdpcontext = (rdpContext*)ps;
	return TRUE;
}

void pf_bkey_pipeline_init(PassthroughClientContext* client, PassthroughServerContext* server,
                           proxyData* pdata)
{
	/*
	 * make client writes sync,
	 * otherwise write buffer might be freed before the write completed.
	 *
	 * deeper explanation:
	 * after the server calls DataReceived callback, it frees the buffer
	 * which was also used by the client to send data to the remote server.
	 * if client writes are async, this buffer might be freed before the write completes,
	 * and that would lead to undefined behavior and wrong data to be sent by the client.
	 *
	 * copying the data to a local buffer in the receive callback wouldn't solve the problem,
	 * because the buffer would still need to be free()'ed after the call to client->SendData,
	 * and the caller can not know when it is safe to free it.
	 */
	client->async_write = FALSE;

	/* Set server and client side references to proxy data */
	client->custom = (void*)pdata;
	server->custom = (void*)pdata;

	/* Set server callbacks */
	server->DataReceived = pf_bkey_data_received_from_client;
	client->DataReceived = pf_bkey_data_received_from_server;
}