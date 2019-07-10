/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * MFA Virtual Channel Extension
 *
 * Copyright 2019 Idan Freiberg <speidy@gmail.com>
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

#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/stream.h>
#include <winpr/sysinfo.h>
#include <freerdp/channels/log.h>

#include "mfa_main.h"

#define CURRENT_VERSION MFA_VERSION_3

static INT64 FileTime_to_POSIX(LPFILETIME ft)
{
	// takes the last modified date
	LARGE_INTEGER date, adjust;
	date.u.HighPart = ft->dwHighDateTime;
	date.u.LowPart = ft->dwLowDateTime;

	// 100-nanoseconds = milliseconds * 10000
	adjust.QuadPart = 11644473600000 * 10000;

	// removes the diff between 1970 and 1601
	date.QuadPart -= adjust.QuadPart;

	// converts back from 100-nanoseconds to seconds
	return date.QuadPart / 10000000;
}

/* Read on msdn about FILETIME and LARGE_INTEGER structs. */
static HANDLE mfa_create_token_timer(INT64 token_exp)
{
	HANDLE timer;
	INT64 now, diff;
	LARGE_INTEGER due;
	FILETIME fileTime;

	GetSystemTimeAsFileTime(&fileTime);
	now = FileTime_to_POSIX(&fileTime);
	diff = token_exp - now;

	WLog_INFO(TAG, "token_validator_create_timer(): now: %ld, exp: %ld, diff: %ld sec", now,
	          token_exp, diff);

	if (now >= token_exp)
	{
		WLog_ERR(TAG, "token_validator_create_timer(): now >= token_exp");
		return NULL;
	}

	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	if (NULL == timer)
	{
		WLog_ERR(TAG, "token_validator_create_timer(): CreateWaitableTimer failed");
		return NULL;
	}

	due.QuadPart = -10000000LL * diff; /* WinApi is the best! */
	if (!SetWaitableTimer(timer, &due, 0, NULL, NULL, 0))
	{
		CloseHandle(timer);
		return NULL;
	}

	return timer;
}

void pf_mfa_wait_for_token_expired_thread(MfaServerContext* context)
{
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;

	if (mfa->exp_thread == NULL || mfa->timer == NULL)
	{
		/* exp_thread is not set, client probably didn't provide a token */
		WLog_INFO(TAG, "[%s]: MFA not initialized, no need to wait", __FUNCTION__);
		return;
	}

	/* wait for expired thread to finish */
	WLog_INFO(TAG, "waiting for exp_thread to exit");
	if (WaitForSingleObject(mfa->exp_thread, INFINITE) != WAIT_OBJECT_0)
	{
		WLog_ERR(TAG, "pf_server_wait_for_mfa_to_finish(): WaitForSingleObject failed!");
		return;
	}

	WLog_INFO(TAG, "exp_thread exited");
}

static void mfa_update_auth_status(MfaServerContext* context, MFA_STATUS status)
{
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	mfa->status = status;
	SetEvent(mfa->auth_status);
}

wStream* mfa_server_packet_new(UINT16 msgType, UINT16 msgFlags, UINT32 dataLen)
{
	wStream* s;
	s = Stream_New(NULL, dataLen + 8);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return NULL;
	}

	Stream_Write_UINT16(s, msgType);
	Stream_Write_UINT16(s, msgFlags);
	/* Write actual length after the entire packet has been constructed. */
	Stream_Seek(s, 4);
	return s;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT mfa_server_packet_send(MfaServerPrivate* mfa, wStream* s)
{
	size_t pos;
	BOOL status;
	UINT32 dataLen;
	UINT32 written;
	pos = Stream_GetPosition(s);
	dataLen = pos - 8;
	Stream_SetPosition(s, 4);
	Stream_Write_UINT32(s, dataLen);
	Stream_SetPosition(s, pos);
	status = WTSVirtualChannelWrite(mfa->ChannelHandle, (PCHAR)Stream_Buffer(s), Stream_Length(s),
	                                &written);
	Stream_Free(s, TRUE);
	return status ? CHANNEL_RC_OK : ERROR_INTERNAL_ERROR;
}

static UINT mfa_server_receive_client_cancelled(MfaServerContext* context, wStream* s,
                                                MFA_HEADER* header)
{
	WLog_INFO(TAG, __FUNCTION__);
	mfa_update_auth_status(context, MFA_STATUS_AUTH_FAIL);
	return CHANNEL_RC_OK;
}

DWORD WINAPI token_validator_exp_thread(LPVOID arg)
{
	DWORD status;
	MfaServerContext* context = arg;
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	HANDLE wait_objects[2] = { mfa->timer, mfa->StopEvent };

	status = WaitForMultipleObjects(ARRAYSIZE(wait_objects), wait_objects, FALSE, INFINITE);

	switch (status)
	{
		case WAIT_FAILED:
			// TODO: how to handle this error?
			// if we just ignore it, the token will never expire
			// TODO: check when WAIT_FAILED occures
			break;
		case WAIT_OBJECT_0:
			WLog_INFO(TAG, "token expired");
			context->ServerTokenResponse(context, MFA_FLAG_TOKEN_EXPIRED);
			IFCALL(context->TokenExpired, context);
			break;
		case WAIT_OBJECT_0 + 1:
			WLog_INFO(TAG, "token_validator_exp_thread: stop event is set!");
			break;
		default:
			break;
	}

	ExitThread(0);
	return 0;
}

static BOOL mfa_server_set_token_info(MfaServerContext* context, INT64 exp, const char* nonce)
{
	context->token_exp = exp;
	context->token_nonce = _strdup(nonce);

	if (!context->token_nonce)
	{
		WLog_ERR(TAG, "strdup failed!");
		return FALSE;
	}

	WLog_INFO(TAG, "token nonce: %s, token expiration date: %d", context->token_nonce, exp);
	return TRUE;
}

static BOOL mfa_server_handle_valid_token(MfaServerContext* context)
{
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	mfa_update_auth_status(context, MFA_STATUS_AUTH_SUCCESS);

	if (context->token_exp > 0)
	{
		mfa->timer = mfa_create_token_timer(context->token_exp);
		if (!mfa->timer)
		{
			WLog_ERR(TAG, "mfa_create_token_timer failed!");
			return FALSE;
		}

		if (!(mfa->exp_thread =
		          CreateThread(NULL, 0, token_validator_exp_thread, context, 0, NULL)))
		{
			WLog_ERR(TAG, "CreateThread failed!");
			CloseHandle(mfa->timer);
			mfa->timer = NULL;
			return FALSE;
		}
	}

	return TRUE;
}

static UINT mfa_server_receive_client_token(MfaServerContext* context, wStream* s,
                                            MFA_HEADER* header)
{
	MFA_CLIENT_TOKEN ct;
	UINT error = CHANNEL_RC_OK;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_ERR(TAG, "not enough data!");
		return ERROR_INVALID_DATA;
	}

	Stream_Read_UINT32(s, ct.cbTokenLen);

	if (Stream_GetRemainingLength(s) < ct.cbTokenLen)
	{
		WLog_ERR(TAG, "not enough data!");
		return ERROR_INVALID_DATA;
	}

	ct.TokenData = malloc(ct.cbTokenLen);
	if (ct.TokenData == NULL)
	{
		WLog_ERR(TAG, "mfa_server_receive_client_token: malloc failed!");
		goto error;
	}

	Stream_Read(s, ct.TokenData, ct.cbTokenLen);

	if (IFCALLRESULT(FALSE, context->VerifyToken, context, &ct))
	{
		if (!mfa_server_handle_valid_token(context))
		{
			context->ServerTokenResponse(context, MFA_FLAG_FAIL);
			goto error;
		}

		context->ServerTokenResponse(context, MFA_FLAG_OK);
	}
	else
	{
		WLog_ERR(TAG, "token verification failed!", error);
		mfa_update_auth_status(context, MFA_STATUS_AUTH_FAIL);
		context->ServerTokenResponse(context, MFA_FLAG_FAIL);
	}

error:
	free(ct.TokenData);
	return error;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_server_receive_pdu(MfaServerContext* context, wStream* s, MFA_HEADER* header)
{
	UINT error;
	WLog_INFO(TAG,
	          "MfaServerReceivePdu: msgType: %" PRIu16 " msgFlags: 0x%04" PRIX16
	          " dataLen: %" PRIu32 "",
	          header->msgType, header->msgFlags, header->dataLen);

	switch (header->msgType)
	{
		case CB_CLIENT_TOKEN:
			if ((error = mfa_server_receive_client_token(context, s, header)))
				WLog_ERR(TAG, "mfa_server_receive_client_token failed with error %" PRIu32 "!",
				         error);
			break;

		case CB_CLIENT_CANCELLED:
			if ((error = mfa_server_receive_client_cancelled(context, s, header)))
				WLog_ERR(TAG, "mfa_server_receive_client_cancelled failed with error %" PRIu32 "!",
				         error);
			break;

		default:
			error = ERROR_INVALID_DATA;
			WLog_DBG(TAG, "Unexpected clipboard PDU type: %" PRIu16 "", header->msgType);
			break;
	}

	return error;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_send_server_ready(MfaServerContext* context, const MFA_SERVER_READY* server_ready)
{
	wStream* s;
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	s = mfa_server_packet_new(CB_SERVER_READY, 0, 2);
	if (!s)
	{
		WLog_ERR(TAG, "mfa_server_packet_new failed!");
		return ERROR_INTERNAL_ERROR;
	}

	Stream_Write_UINT16(s, server_ready->version); /* version (2 bytes) */

	WLog_DBG(TAG, "mfa_send_server_ready");
	return mfa_server_packet_send(mfa, s);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_send_server_token_response(MfaServerContext* context, const enum MFA_FLAGS flags)
{
	wStream* s;
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	s = mfa_server_packet_new(CB_SERVER_TOKEN_RESPONSE, flags, 0);
	if (!s)
	{
		WLog_ERR(TAG, "mfa_server_packet_new failed!");
		return ERROR_INTERNAL_ERROR;
	}

	WLog_DBG(TAG, "mfa_send_server_token_response");
	return mfa_server_packet_send(mfa, s);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_server_init(MfaServerContext* context)
{
	UINT error = CHANNEL_RC_OK;

	/* Send server ready PDU */
	MFA_SERVER_READY sr;
	sr.version = CURRENT_VERSION;

	if ((error = context->ServerReady(context, &sr)))
	{
		WLog_ERR(TAG, "ServerReady failed with error %" PRIu32 "!", error);
		return error;
	}

	return error;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT mfa_server_read(MfaServerContext* context)
{
	wStream* s;
	size_t position;
	DWORD BytesToRead;
	DWORD BytesReturned;
	MFA_HEADER header;
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	UINT error;
	DWORD status;
	s = mfa->s;

	if (Stream_GetPosition(s) < MFA_HEADER_LENGTH)
	{
		BytesReturned = 0;
		BytesToRead = MFA_HEADER_LENGTH - Stream_GetPosition(s);
		status = WaitForSingleObject(mfa->ChannelEvent, 0);

		if (status == WAIT_FAILED)
		{
			error = GetLastError();
			WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "", error);
			return error;
		}

		if (status == WAIT_TIMEOUT)
			return CHANNEL_RC_OK;

		if (!WTSVirtualChannelRead(mfa->ChannelHandle, 0, (PCHAR)Stream_Pointer(s), BytesToRead,
		                           &BytesReturned))
		{
			WLog_ERR(TAG, "WTSVirtualChannelRead failed!");
			return ERROR_INTERNAL_ERROR;
		}

		Stream_Seek(s, BytesReturned);
	}

	if (Stream_GetPosition(s) >= MFA_HEADER_LENGTH)
	{
		position = Stream_GetPosition(s);
		Stream_SetPosition(s, 0);
		Stream_Read_UINT16(s, header.msgType);  /* msgType (2 bytes) */
		Stream_Read_UINT16(s, header.msgFlags); /* msgFlags (2 bytes) */
		Stream_Read_UINT32(s, header.dataLen);  /* dataLen (4 bytes) */

		if (!Stream_EnsureCapacity(s, (header.dataLen + MFA_HEADER_LENGTH)))
		{
			WLog_ERR(TAG, "Stream_EnsureCapacity failed!");
			return CHANNEL_RC_NO_MEMORY;
		}

		Stream_SetPosition(s, position);

		if (Stream_GetPosition(s) < (header.dataLen + MFA_HEADER_LENGTH))
		{
			BytesReturned = 0;
			BytesToRead = (header.dataLen + MFA_HEADER_LENGTH) - Stream_GetPosition(s);
			status = WaitForSingleObject(mfa->ChannelEvent, 0);

			if (status == WAIT_FAILED)
			{
				error = GetLastError();
				WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "", error);
				return error;
			}

			if (status == WAIT_TIMEOUT)
				return CHANNEL_RC_OK;

			if (!WTSVirtualChannelRead(mfa->ChannelHandle, 0, (PCHAR)Stream_Pointer(s), BytesToRead,
			                           &BytesReturned))
			{
				WLog_ERR(TAG, "WTSVirtualChannelRead failed!");
				return ERROR_INTERNAL_ERROR;
			}

			Stream_Seek(s, BytesReturned);
		}

		if (Stream_GetPosition(s) >= (header.dataLen + MFA_HEADER_LENGTH))
		{
			Stream_SetPosition(s, (header.dataLen + MFA_HEADER_LENGTH));
			Stream_SealLength(s);
			Stream_SetPosition(s, MFA_HEADER_LENGTH);

			if ((error = mfa_server_receive_pdu(context, s, &header)))
			{
				WLog_ERR(TAG, "mfa_server_receive_pdu failed with error code %" PRIu32 "!", error);
				return error;
			}

			Stream_SetPosition(s, 0);
			/* check for trailing zero bytes */
			status = WaitForSingleObject(mfa->ChannelEvent, 0);

			if (status == WAIT_FAILED)
			{
				error = GetLastError();
				WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "", error);
				return error;
			}

			if (status == WAIT_TIMEOUT)
				return CHANNEL_RC_OK;

			BytesReturned = 0;
			BytesToRead = 4;

			if (!WTSVirtualChannelRead(mfa->ChannelHandle, 0, (PCHAR)Stream_Pointer(s), BytesToRead,
			                           &BytesReturned))
			{
				WLog_ERR(TAG, "WTSVirtualChannelRead failed!");
				return ERROR_INTERNAL_ERROR;
			}

			if (BytesReturned == 4)
			{
				Stream_Read_UINT16(s, header.msgType);  /* msgType (2 bytes) */
				Stream_Read_UINT16(s, header.msgFlags); /* msgFlags (2 bytes) */

				if (!header.msgType)
				{
					/* ignore trailing bytes */
					Stream_SetPosition(s, 0);
				}
			}
			else
			{
				Stream_Seek(s, BytesReturned);
			}
		}
	}

	return CHANNEL_RC_OK;
}

static DWORD WINAPI mfa_server_thread(LPVOID arg)
{
	DWORD status;
	DWORD nCount;
	HANDLE events[8];
	HANDLE ChannelEvent;
	MfaServerContext* context = (MfaServerContext*)arg;
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	UINT error;

	ChannelEvent = context->GetEventHandle(context);
	nCount = 0;
	events[nCount++] = mfa->StopEvent;
	events[nCount++] = ChannelEvent;

	if ((error = mfa_server_init(context)))
	{
		WLog_ERR(TAG, "mfa_server_init failed with error %" PRIu32 "!", error);
		goto out;
	}

	while (1)
	{
		status = WaitForMultipleObjects(nCount, events, FALSE, INFINITE);

		if (status == WAIT_FAILED)
		{
			error = GetLastError();
			WLog_ERR(TAG, "WaitForMultipleObjects failed with error %" PRIu32 "", error);
			goto out;
		}

		status = WaitForSingleObject(mfa->StopEvent, 0);

		if (status == WAIT_FAILED)
		{
			error = GetLastError();
			WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "", error);
			goto out;
		}

		if (status == WAIT_OBJECT_0)
			break;

		status = WaitForSingleObject(ChannelEvent, 0);

		if (status == WAIT_FAILED)
		{
			error = GetLastError();
			WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "", error);
			goto out;
		}

		if (status == WAIT_OBJECT_0)
		{
			if ((error = context->CheckEventHandle(context)))
			{
				WLog_ERR(TAG, "CheckEventHandle failed with error %" PRIu32 "!", error);
				break;
			}
		}
	}

out:

	if (error && context->rdpcontext)
		setChannelError(context->rdpcontext, error, "mfa_server_thread reported an error");

	ExitThread(error);
	return error;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_server_open(MfaServerContext* context)
{
	void* buffer = NULL;
	DWORD BytesReturned = 0;
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	mfa->ChannelHandle = WTSVirtualChannelOpen(mfa->vcm, WTS_CURRENT_SESSION, MFA_SVC_CHANNEL_NAME);

	if (!mfa->ChannelHandle)
	{
		WLog_ERR(TAG, "WTSVirtualChannelOpen for mfa failed!");
		return ERROR_INTERNAL_ERROR;
	}

	mfa->ChannelEvent = NULL;

	if (WTSVirtualChannelQuery(mfa->ChannelHandle, WTSVirtualEventHandle, &buffer, &BytesReturned))
	{
		if (BytesReturned != sizeof(HANDLE))
		{
			WLog_ERR(TAG, "BytesReturned has not size of HANDLE!");
			return ERROR_INTERNAL_ERROR;
		}

		CopyMemory(&(mfa->ChannelEvent), buffer, sizeof(HANDLE));
		WTSFreeMemory(buffer);
	}

	if (!mfa->ChannelEvent)
	{
		WLog_ERR(TAG, "WTSVirtualChannelQuery for mfa failed!");
		return ERROR_INTERNAL_ERROR;
	}

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_server_close(MfaServerContext* context)
{
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;

	if (mfa->ChannelHandle)
	{
		WTSVirtualChannelClose(mfa->ChannelHandle);
		mfa->ChannelHandle = NULL;
	}

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_server_start(MfaServerContext* context)
{
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	UINT error;

	if (!mfa->ChannelHandle)
	{
		if ((error = context->Open(context)))
		{
			WLog_ERR(TAG, "Open failed!");
			return error;
		}
	}

	if (!(mfa->StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL)))
	{
		WLog_ERR(TAG, "CreateEvent failed!");
		return ERROR_INTERNAL_ERROR;
	}

	if (!(mfa->Thread = CreateThread(NULL, 0, mfa_server_thread, (void*)context, 0, NULL)))
	{
		WLog_ERR(TAG, "CreateThread failed!");
		CloseHandle(mfa->StopEvent);
		mfa->StopEvent = NULL;
		return ERROR_INTERNAL_ERROR;
	}

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_server_stop(MfaServerContext* context)
{
	UINT error = CHANNEL_RC_OK;
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;

	if (mfa->StopEvent)
	{
		SetEvent(mfa->StopEvent);

		if (WaitForSingleObject(mfa->Thread, INFINITE) == WAIT_FAILED)
		{
			error = GetLastError();
			WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "", error);
			return error;
		}

		pf_mfa_wait_for_token_expired_thread(context);

		CloseHandle(mfa->Thread);
		CloseHandle(mfa->StopEvent);
	}

	if (mfa->ChannelHandle)
		return context->Close(context);

	return error;
}

static HANDLE mfa_server_get_event_handle(MfaServerContext* context)
{
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	return mfa->ChannelEvent;
}

static MFA_STATUS mfa_wait_for_auth(MfaServerContext* context, HANDLE cancelWait, DWORD timeout)
{
	DWORD status;
	MfaServerPrivate* mfa = (MfaServerPrivate*)context->handle;
	HANDLE handles[2] = { mfa->auth_status, cancelWait };
	status = WaitForMultipleObjects(2, handles, FALSE, timeout);

	switch (status)
	{
		case WAIT_FAILED:
			WLog_ERR(TAG, "mfa_wait_for_auth: WAIT_FAILED");
			return MFA_STATUS_AUTH_FAIL;
		case WAIT_OBJECT_0:
			/* auth status was updated */
			return mfa->status;
		case WAIT_OBJECT_0 + 1:
			/* session ended */
			return MFA_STATUS_AUTH_FAIL;
		case WAIT_TIMEOUT:
			WLog_INFO(TAG, "pf_client_wait_for_mfa: timeout passed.");
			return MFA_STATUS_AUTH_TIMEOUT;
	}

	return mfa->status;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT mfa_server_check_event_handle(MfaServerContext* context)
{
	return mfa_server_read(context);
}

MfaServerContext* mfa_server_context_new(HANDLE vcm)
{
	MfaServerContext* context;
	MfaServerPrivate* mfa;

	context = (MfaServerContext*)calloc(1, sizeof(MfaServerContext));
	if (!context)
		return NULL;

	context->Open = mfa_server_open;
	context->Close = mfa_server_close;
	context->Start = mfa_server_start;
	context->Stop = mfa_server_stop;
	context->GetEventHandle = mfa_server_get_event_handle;
	context->CheckEventHandle = mfa_server_check_event_handle;
	context->WaitForAuth = mfa_wait_for_auth;

	context->SetTokenInfo = mfa_server_set_token_info;
	context->ServerReady = mfa_send_server_ready;
	context->ServerTokenResponse = mfa_send_server_token_response;

	/* message callbacks */
	context->VerifyToken = NULL;

	mfa = context->handle = (MfaServerPrivate*)calloc(1, sizeof(MfaServerPrivate));

	if (!mfa)
	{
		WLog_ERR(TAG, "calloc MfaServerPrivate failed!");
		goto error;
	}

	mfa->status = MFA_STATUS_UNINITIALIZED;

	if (!(mfa->auth_status = CreateEvent(NULL, TRUE, FALSE, NULL)))
	{
		WLog_ERR(TAG, "CreateEvent failed!");
		goto error;
	}

	mfa->vcm = vcm;
	mfa->s = Stream_New(NULL, 4096);

	if (!mfa->s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		goto error;
	}

	return context;
error:
	mfa_server_context_free(context);
	return NULL;
}

void mfa_server_context_free(MfaServerContext* context)
{
	MfaServerPrivate* mfa;

	if (!context)
		return;

	mfa = (MfaServerPrivate*)context->handle;

	if (mfa)
	{
		Stream_Free(mfa->s, TRUE);

		if (mfa->auth_status)
			CloseHandle(mfa->auth_status);

		if (mfa->exp_thread)
			CloseHandle(mfa->exp_thread);

		if (mfa->timer)
			CloseHandle(mfa->timer);
	}

	if (context->token_nonce)
	{
		free(context->token_nonce);
		context->token_nonce = NULL;
	}

	free(context->handle);
	free(context);
}
