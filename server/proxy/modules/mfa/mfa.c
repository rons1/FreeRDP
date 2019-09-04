/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server MFA module
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mfa.h"

static TokenValidator* g_token_validator = NULL;
static proxyPluginsManager* g_plugins_manager = NULL;

static mfaConfig config = { 0 };

static BOOL mfa_update_idle_timer(proxyData* pdata);

static void mfa_session_free(mfaSession* session)
{
	if (session)
	{
		CloseHandle(session->auth);
		CloseHandle(session->idle_timer);
		free(session);
	}
}

static mfaSession* mfa_session_new(proxyData* pdata)
{
	mfaSession* session = calloc(1, sizeof(mfaSession));
	if (!session)
		return NULL;

	session->pdata = pdata;
	session->idle_timer = CreateWaitableTimer(NULL, TRUE, NULL);
	if (!session->idle_timer)
		goto error;

	session->auth = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!session->auth)
		goto error;

	return session;

error:
	mfa_session_free(session);
	return NULL;
}

static BOOL mfa_block_until_auth(MfaServerContext* mfa)
{
	mfaSession* session;
	proxyData* pdata;
	HANDLE waitHandles[2];

	if (!mfa)
		return FALSE;

	session = (mfaSession*)mfa->custom;
	pdata = session->pdata;

	/* init wait handles */
	waitHandles[0] = session->auth;
	waitHandles[1] = pdata->abort_event;

	switch (WaitForMultipleObjects(2, waitHandles, FALSE, config.auth_timeout_sec * 1000))
	{
		case WAIT_FAILED:
			WLog_ERR(TAG, "[%s]: wait failed", __FUNCTION__);
			return FALSE;
		case WAIT_OBJECT_0:
			/* auth success */
			return TRUE;
		case WAIT_OBJECT_0 + 1:
			/* session aborted */
			return TRUE;
		case WAIT_TIMEOUT:
			WLog_INFO(TAG, "auth timeout exceeded, closing connection");
			mfa->ServerTokenResponse(mfa, MFA_FLAG_TIMEOUT);
			return FALSE;
		default:
			return FALSE;
	}

	return TRUE;
}

static BOOL mfa_pre_connect(proxyData* pdata)
{
	MfaServerContext* mfa;

	mfa = g_plugins_manager->GetPluginData(PLUGIN_NAME, pdata);
	if (mfa == NULL)
	{
		WLog_ERR(TAG, "mfa server uninitialized!");
		return FALSE;
	}

	return mfa_block_until_auth(mfa);
}

static BOOL pf_mfa_verify_token(MfaServerContext* context, const MFA_CLIENT_TOKEN* ct)
{
	rdpContext* peer_context = context->rdpcontext;
	struct token_response_t resp;
	pServerContext* ps = (pServerContext*)context->rdpcontext;

	resp = token_validator_validate_token(g_token_validator, (const char*)ct->TokenData,
	                                      ct->cbTokenLen, peer_context->settings->Username);

	if (resp.verification_result == VERIFY_SUCCESS)
	{
		LOG_INFO(TAG, ps, "token is validated, authentication succeeded");
		return context->SetTokenInfo(context, resp.exp, resp.nonce);
	}

	switch (resp.verification_result)
	{
		case VERIFY_TOKEN_SIGNATURE_FAILED:
			LOG_WARN(TAG, ps,
			         "token verification process failed: token signature verification failed!");
			break;
		case VERIFY_TOKEN_ALREADY_USED:
			LOG_WARN(TAG, ps, "token verification process failed: token already used!");
			break;
		case VERIFY_TOKEN_INVALID_AUDIENCE:
			LOG_WARN(TAG, ps, "token verification process failed: invalid audience!");
			break;
		case VERIFY_TOKEN_INVALID_ISSUER:
			LOG_WARN(TAG, ps, "token verification process failed: invalid issuer!");
			break;
		case VERIFY_TOKEN_IS_TOO_OLD:
			LOG_WARN(TAG, ps,
			         "token verification process failed: token skew error: token is too old!");
			break;
		case VERIFY_FAILED_UNKNOWN:
			LOG_WARN(TAG, ps, "token verification process failed: reason unknown");
			break;
		default:
			LOG_ERR(TAG, ps, "received unknown verification result code");
			break;
	}

	return FALSE;
}

static void mfa_token_expired(MfaServerContext* context)
{
	mfaSession* session = (mfaSession*)context->custom;
	proxyData* pdata = session->pdata;
	context->ServerTokenResponse(context, MFA_FLAG_TOKEN_EXPIRED);
	g_plugins_manager->AbortConnect(pdata);
}

static void mfa_abort_connect(MfaServerContext* context)
{
	mfaSession* session = (mfaSession*)context->custom;
	proxyData* pdata = session->pdata;
	g_plugins_manager->AbortConnect(pdata);
}

static BOOL mfa_auth_result(MfaServerContext* context, MFA_STATUS result)
{
	mfaSession* session = (mfaSession*)context->custom;
	proxyData* pdata = session->pdata;

	LOG_INFO(TAG, pdata->ps, "authentication status updated");
	switch (result)
	{
		case MFA_STATUS_AUTHENTICATED:
			/* reset idle timer */
			mfa_update_idle_timer(session->pdata);

			SetEvent(session->auth);
			return context->ServerTokenResponse(context, MFA_FLAG_OK);
			break;
		case MFA_STATUS_AUTH_FAIL:
			return context->ServerTokenResponse(context, MFA_FLAG_FAIL);
			break;
		case MFA_STATUS_AUTH_TIMEOUT:
			return context->ServerTokenResponse(context, MFA_FLAG_TIMEOUT);
		default:
			WLog_ERR(TAG, "auth result: unknown result %d", result);
			return FALSE;
	}
}

static BOOL mfa_register_channel(proxyData* pdata)
{
	MfaServerContext* mfa = NULL;
	mfaSession* session = NULL;
	pServerContext* ps = pdata->ps;

	if (!WTSVirtualChannelManagerIsChannelJoined(ps->vcm, MFA_SVC_CHANNEL_NAME))
	{
		LOG_ERR(TAG, ps, "mfa_register_channel: client did not connect with MFA!");
		return FALSE;
	}

	mfa = mfa_server_context_new(ps->vcm, config.mfa_audience);
	if (!mfa)
		return FALSE;

	session = mfa_session_new(pdata);
	if (!session)
		goto error;

	mfa->custom = session;
	mfa->rdpcontext = (rdpContext*)ps;

	/* MFA callbacks */
	mfa->TokenExpired = mfa_token_expired;
	mfa->AuthCancelled = mfa_abort_connect;
	mfa->AuthenticationResult = mfa_auth_result;
	mfa->VerifyToken = pf_mfa_verify_token;

	/* save pointer to MFA server */
	g_plugins_manager->SetPluginData(PLUGIN_NAME, pdata, mfa);
	return mfa->Start(mfa) == CHANNEL_RC_OK;

error:
	mfa_session_free(session);
	mfa_server_context_free(mfa);
	return FALSE;
}

static BOOL mfa_free_channel(proxyData* pdata)
{
	MfaServerContext* mfa = g_plugins_manager->GetPluginData(PLUGIN_NAME, pdata);

	if (mfa)
	{
		mfaSession* session = (mfaSession*)mfa->custom;
		mfa_session_free(session);

		/* make sure token's nonce is removed from memory */
		token_validator_mark_token_unused(g_token_validator, mfa->token_nonce);

		WLog_INFO(TAG, "stopping MFA server");
		mfa->Stop(mfa);
		mfa_server_context_free(mfa);
	}

	return TRUE;
}
static void CALLBACK mfa_session_idle_event(LPVOID lpArg, DWORD dwTimerLowValue,
                                            DWORD dwTimerHighValue)
{
	MfaServerContext* mfa = (MfaServerContext*)lpArg;
	mfaSession* session = (mfaSession*)mfa->custom;
	proxyData* pdata = session->pdata;

	if (mfa->GetStatus(mfa) != MFA_STATUS_AUTHENTICATED)
	{
		/* session is already at unauthenticated state, abort the connection */
		g_plugins_manager->AbortConnect(pdata);
		return;
	}

	LOG_INFO(TAG, pdata->ps, "mfa: session idle, forcing client to refresh its auth token");

	/* force client to refresh its authentication token */
	token_validator_mark_token_unused(g_token_validator, mfa->token_nonce);
	mfa->ForceRefreshToken(mfa);
}

static BOOL mfa_update_idle_timer(proxyData* pdata)
{
	MfaServerContext* mfa;
	mfaSession* session;
	LARGE_INTEGER due;

	mfa = g_plugins_manager->GetPluginData(PLUGIN_NAME, pdata);
	if (!mfa)
		return FALSE;

	session = (mfaSession*)mfa->custom;

	due.QuadPart = -1 * config.refresh_token_interval * 10000000;
	LOG_DBG(TAG, session->pdata->ps, "reset refresh token timer");

	return SetWaitableTimer(session->idle_timer, // Handle to the timer object.
	                        &due,                // When timer will become signaled.
	                        0,
	                        mfa_session_idle_event, // Completion routine.
	                        (void*)mfa,             // Argument to the completion routine.
	                        FALSE);                 // Do not restore a suspended system.
}

static BOOL mfa_handle_keyboard_and_mouse_event(proxyData* pdata, void* param)
{
	MfaServerContext* mfa = g_plugins_manager->GetPluginData(PLUGIN_NAME, pdata);
	mfa_update_idle_timer(pdata);

	/* Only allow mouse and keyboard events to be proxied if session is authenticated */
	if (mfa->GetStatus(mfa) != MFA_STATUS_AUTHENTICATED)
		return FALSE;

	return TRUE;
}

static BOOL mfa_config_load()
{
	BOOL ok = FALSE;
	wIniFile* ini = IniFile_New();

	if (!ini)
	{
		WLog_ERR(TAG, "mfa_load_config: IniFile_New() failed!");
		return FALSE;
	}

	if (IniFile_ReadFile(ini, "mfa.ini") < 0)
	{
		WLog_ERR(TAG, "mfa_load_config: IniFile_ReadFile() failed!");
		goto out;
	}

	config.mfa_adfs_base_url = _strdup(pf_config_get_str(ini, "MFA", "AdfsBaseUrl"));
	config.mfa_audience = _strdup(pf_config_get_str(ini, "MFA", "Audience"));
	config.insecure_ssl = pf_config_get_bool(ini, "MFA", "InsecureSSL");
	config.token_skew_minutes = IniFile_GetKeyValueInt(ini, "MFA", "TokenSkewMinutes");
	config.auth_timeout_sec = IniFile_GetKeyValueInt(ini, "MFA", "WaitTimeoutSec");
	config.refresh_token_interval = IniFile_GetKeyValueInt(ini, "MFA", "RefreshTokenIntervalSec");
	ok = TRUE;

out:
	IniFile_Free(ini);
	return ok;
}

static void mfa_config_free()
{
	free(config.mfa_adfs_base_url);
	free(config.mfa_audience);
}

static BOOL mfa_plugin_unload()
{
	mfa_config_free();
	token_validator_free(g_token_validator);
	g_plugins_manager = NULL;
	return TRUE;
}

static proxyPlugin mfa_plugin = {
	PLUGIN_NAME,                         /* name */
	PLUGIN_DESC,                         /* description */
	mfa_plugin_unload,                   /* PluginUnload */
	mfa_pre_connect,                     /* ClientPreConnect */
	NULL,                                /* ClientPostConnect */
	NULL,                                /* ClientLoginFailure */
	NULL,                                /* ClientEndPaint */
	NULL,                                /* ServerPostConnect */
	mfa_register_channel,                /* ServerChannelsInit */
	mfa_free_channel,                    /* ServerChannelsFree */
	NULL,                                /* ServerSessionEnd */
	mfa_handle_keyboard_and_mouse_event, /* KeyboardEvent */
	mfa_handle_keyboard_and_mouse_event, /* MouseEvent */
	NULL,                                /* client passthrough channels data */
	NULL,                                /* server passthrough channels data */
};

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
#ifndef WITH_MFA
	WLog_WARN(TAG, "MFA module compiled without server side channel.");
	return FALSE;
#endif

	g_plugins_manager = plugins_manager;

	if (!mfa_config_load())
	{
		WLog_ERR(TAG, "mfa: module_init: mfa_config_load failed!");
		goto error;
	}

	g_token_validator = token_validator_init(config.mfa_adfs_base_url, config.mfa_audience,
	                                         config.token_skew_minutes, config.insecure_ssl);

	if (!g_token_validator)
		goto error;

	if (!plugins_manager->RegisterPlugin(&mfa_plugin))
		goto error;

	return TRUE;
error:
	token_validator_free(g_token_validator);
	mfa_config_free(config);
	return FALSE;
}
