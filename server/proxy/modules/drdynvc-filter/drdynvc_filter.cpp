/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server Demo C++ Module
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

#include <iostream>

#include "modules_api.h"
#include "pf_log.h"

#define TAG MODULE_TAG("drdynvc_filter")

static constexpr char plugin_name[] = "drdynvc filter";
static constexpr char plugin_desc[] = "filters which dynamic virtual channels can be proxied";

static proxyPluginsManager* g_plugins_manager = NULL;

static constexpr int CREATE_REQUEST_PDU = 0x01;

static INLINE UINT32 drdynvc_cblen_to_bytes(int cbLen)
{
	switch (cbLen)
	{
		case 0:
			return 1;

		case 1:
			return 2;

		default:
			return 4;
	}
}

static BOOL drdynvc_filter_is_channel_allowed(const char* name)
{
	std::string channel_name(name);
	return TRUE;
}

static BOOL drdynvc_filter_order_recv(proxyData* pdata, wStream* s)
{
	int value;
	int cmd;
	int sp;
	int cbChId;

	if (Stream_GetRemainingLength(s) < 1)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT8(s, value);
	cmd = (value & 0xf0) >> 4;
	sp = (value & 0x0c) >> 2;
	cbChId = (value & 0x03) >> 0;

	if (cmd == CREATE_REQUEST_PDU)
	{
		UINT32 ch_id_bytes_count = drdynvc_cblen_to_bytes(cbChId);
		size_t length;
		char* name = NULL;

		if (Stream_GetRemainingLength(s) < ch_id_bytes_count)
			return FALSE;

		Stream_Seek(s, ch_id_bytes_count); /* skip channel id */
		name = (char*)Stream_Pointer(s);
		length = Stream_GetRemainingLength(s);

		if (strnlen(name, length) >= length)
			return FALSE;

		std::cout << name << std::endl;
		LOG_INFO(TAG, pdata->ps, "[passthrough] drdynvc: create request: name=%s", name);
		return drdynvc_filter_is_channel_allowed(name);
	}

	return TRUE;
}

static BOOL drdynvc_filter_plugin_client_channel_data(proxyData* pdata, void* param)
{
	wStream s;
	auto ev = static_cast<proxyChannelDataEventInfo*>(param);

	if (ev == NULL)
		return FALSE;

	if (strcmp(ev->channel_name, "drdynvc") != 0)
		return TRUE;

	Stream_StaticInit(&s, (BYTE*)ev->data, ev->data_len);
	return drdynvc_filter_order_recv(pdata, &s);
}

static proxyPlugin demo_plugin = {
	plugin_name,                               /* name */
	plugin_desc,                               /* description */
	NULL,                                      /* PluginUnload */
	NULL,                                      /* ClientPreConnect */
	NULL,                                      /* ClientPostConnect */
	NULL,                                      /* ClientLoginFailure */
	NULL,                                      /* ClientEndPaint */
	NULL,                                      /* ServerPostConnect */
	NULL,                                      /* ServerChannelsInit */
	NULL,                                      /* ServerChannelsFree */
	NULL,                                      /* ServerSessionEnd */
	NULL,                                      /* KeyboardEvent */
	NULL,                                      /* MouseEvent */
	drdynvc_filter_plugin_client_channel_data, /* ClientChannelData */
	NULL,                                      /* ServerChannelData */
};

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
	g_plugins_manager = plugins_manager;
	return plugins_manager->RegisterPlugin(&demo_plugin);
}
