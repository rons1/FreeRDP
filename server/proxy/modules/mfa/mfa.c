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

#include <freerdp/server/mfa.h>

#include "modules_api.h"
#include "pf_context.h"
#include "pf_log.h"
#include "pf_config.h"
#include "token_validator.h"

#define TAG PROXY_TAG("mfa")

static TokenValidator* g_token_validator = NULL;
static proxyPluginsManager* g_plugins_manager = NULL;

#define PLUGIN_NAME "mfa"
#define PLUGIN_DESC "multi factor authentication over RDP"

struct mfa_module_config
{
	char* mfa_adfs_base_url;
	char* mfa_audience;
	BOOL insecure_ssl;
	INT64 token_skew_minutes;
	INT64 auth_timeout;
};

static struct mfa_module_config config = { 0 };

static BOOL mfa_pre_connect(proxyData* pdata)
{
	pServerContext* ps = pdata->ps;
	MFA_STATUS mfa_st;
	MfaServerContext* mfa;

	mfa = g_plugins_manager->GetPluginData(PLUGIN_NAME, pdata);
	if (mfa == NULL)
	{
		WLog_ERR(TAG, "mfa server uninitialized!");
		return FALSE;
	}

	/* wait for authentication, and cancel wait if session ends */
	mfa_st = mfa->WaitForAuth(mfa, ps->pdata->abort_event, 20 * 1000);
	switch (mfa_st)
	{
		case MFA_STATUS_AUTH_FAIL:
			WLog_INFO(TAG, "authentication failed!");
			return FALSE;
		case MFA_STATUS_AUTH_TIMEOUT:
			WLog_INFO(TAG, "auth timeout exeeced, closing connection");
			mfa->ServerTokenResponse(mfa, MFA_FLAG_TIMEOUT);
			return FALSE;
		case MFA_STATUS_AUTH_SUCCESS:
			WLog_INFO(TAG, "authentication succeeded!");
			return TRUE;
		default:
			WLog_ERR(TAG, "unknown auth status!");
			return FALSE;
	}
}

static BOOL pf_mfa_verify_token(MfaServerContext* context, const MFA_CLIENT_TOKEN* ct)
{
	struct token_response_t resp;
	const char* token = (const char*)ct->TokenData;
	UINT32 token_len = ct->cbTokenLen;

	resp = token_validator_validate_token(g_token_validator, token, token_len);
	if (resp.is_valid)
		return context->SetTokenInfo(context, resp.exp, resp.nonce);

	return FALSE;
}

static void mfa_token_expired(MfaServerContext* context)
{
	pServerContext* ps = (pServerContext*)context->rdpcontext;
	g_plugins_manager->AbortConnect(ps->pdata);
}

static BOOL mfa_register_channel(proxyData* pdata)
{
	MfaServerContext* mfa;
	pServerContext* ps = pdata->ps;

	if (!WTSVirtualChannelManagerIsChannelJoined(ps->vcm, MFA_SVC_CHANNEL_NAME))
	{
		WLog_ERR(TAG, "mfa_register_channel: client did not connect with MFA!");
		return FALSE;
	}

	mfa = mfa_server_context_new(ps->vcm);

	if (!mfa)
	{
		return FALSE;
	}

	/* save pointer to MFA server */
	g_plugins_manager->SetPluginData(PLUGIN_NAME, pdata, mfa);

	mfa->custom = pdata;
	mfa->rdpcontext = (rdpContext*)ps;

	/* MFA callbacks */
	mfa->TokenExpired = mfa_token_expired;
	mfa->VerifyToken = pf_mfa_verify_token;

	return mfa->Start(mfa) == CHANNEL_RC_OK;
}

static BOOL mfa_free_channel(proxyData* pdata)
{
	MfaServerContext* mfa = g_plugins_manager->GetPluginData(PLUGIN_NAME, pdata);

	if (mfa)
	{
		/* make sure token's nonce is removed from memory */
		token_validator_mark_token_unused(g_token_validator, mfa->token_nonce);

		WLog_INFO(TAG, "stopping MFA server");
		mfa->Stop(mfa);
		WLog_INFO(TAG, "freeing MFA server");
		mfa_server_context_free(mfa);
	}

	return TRUE;
}

static BOOL mfa_config_load()
{
	BOOL ok = FALSE;
	wIniFile* ini = IniFile_New();

	if (!ini)
	{
		WLog_ERR(TAG, "mfa_load_config(): IniFile_New() failed!");
		return FALSE;
	}

	if (IniFile_ReadFile(ini, "mfa.ini") < 0)
	{
		WLog_ERR(TAG, "mfa_load_config(): IniFile_ReadFile() failed!");
		goto out;
	}

	config.mfa_adfs_base_url = _strdup(pf_config_get_str(ini, "MFA", "AdfsBaseUrl"));
	config.mfa_audience = _strdup(pf_config_get_str(ini, "MFA", "Audience"));
	config.insecure_ssl = pf_config_get_bool(ini, "MFA", "InsecureSSL");
	config.token_skew_minutes = IniFile_GetKeyValueInt(ini, "MFA", "TokenSkewMinutes");
	config.auth_timeout = IniFile_GetKeyValueInt(ini, "MFA", "WaitTimeout");
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
	return TRUE;
}

static proxyPlugin mfa_plugin = {
	PLUGIN_NAME,          /* name */
	PLUGIN_DESC,          /* description */
	mfa_pre_connect,      /* ClientPreConnect */
	NULL,                 /* ClientLoginFailure */
	NULL,                 /* ServerPostConnect */
	mfa_register_channel, /* ServerChannelsInit */
	mfa_free_channel,     /* ServerChannelsFree */
	NULL,                 /* KeyboardEvent */
	NULL,                 /* MouseEvent */
	mfa_plugin_unload     /* PluginUnload */
};

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
#ifndef WITH_MFA
	return FALSE;
#endif

	g_plugins_manager = plugins_manager;

	if (!mfa_config_load())
	{
		WLog_ERR(TAG, "mfa: module_init: mfa_config_load failed!");
		return FALSE;
	}

	g_token_validator = token_validator_init(config.mfa_adfs_base_url, config.mfa_audience,
	                                         config.token_skew_minutes, config.insecure_ssl);

	if (!g_token_validator)
	{
		mfa_config_free();
		WLog_ERR(TAG, "token_validator_init failed!");
		return FALSE;
	}

	if (!plugins_manager->RegisterPlugin(&mfa_plugin))
	{
		token_validator_free(g_token_validator);
		mfa_config_free();
		return FALSE;
	}

	return TRUE;
}
