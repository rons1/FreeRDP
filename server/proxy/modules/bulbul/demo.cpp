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
#include <winpr/wtsapi.h>

#include "modules_api.h"

#define TAG MODULE_TAG("demo")

static constexpr char plugin_name[] = "demo";
static constexpr char plugin_desc[] = "user experience";
static char channel_name[] = "bulbul";

static proxyPluginsManager* g_plugins_manager = NULL;

static BOOL bulbul_server_channels_init(proxyData* pdata)
{
	pServerContext* ps = pdata->ps;

	if (!WTSVirtualChannelManagerIsChannelJoined(ps->vcm, channel_name))
	{
		/* channel not requested */
		WLog_INFO(TAG, "user experience channel was not requested");
		return TRUE;
	}

	HANDLE channelHandle = WTSVirtualChannelOpen(ps->vcm, WTS_CURRENT_SESSION, channel_name);
	if (!channelHandle)
		return FALSE;

	g_plugins_manager->SetPluginData(plugin_name, pdata, (void*)channelHandle);
	return TRUE;
}

static BOOL bulbul_server_channels_free(proxyData* pdata)
{
	HANDLE channelHandle;

	channelHandle = (HANDLE)g_plugins_manager->GetPluginData(channel_name, pdata);
	if (!channelHandle)
		return TRUE;

	if (!WTSVirtualChannelClose(channelHandle))
	{
		WLog_ERR(TAG, "WTSVirtualChannelClose failed!");
		return FALSE;
	}

	g_plugins_manager->SetPluginData(channel_name, pdata, NULL);
	return TRUE;
}

static BOOL send_message(proxyData* pdata, const BYTE* message, size_t len)
{
	HANDLE channelHandle;
	DWORD written;

	channelHandle = (HANDLE)g_plugins_manager->GetPluginData(channel_name, pdata);
	if (!channelHandle)
		return FALSE;

	if (!WTSVirtualChannelWrite(channelHandle, (PCHAR)message, len, &written))
	{
		WLog_ERR(TAG, "WTSVirtualChannelWrite failed!");
		return FALSE;
	}

	return TRUE;
}

static proxyPlugin demo_plugin = {
	plugin_name,                 /* name */
	plugin_desc,                 /* description */
	NULL,                        /* PluginUnload */
	NULL,                        /* ClientPreConnect */
	NULL,                        /* ClientPostConnect */
	NULL,                        /* ClientLoginFailure */
	NULL,                        /* ClientEndPaint */
	NULL,                        /* ServerPostConnect */
	bulbul_server_channels_init, /* ServerChannelsInit */
	bulbul_server_channels_free, /* ServerChannelsFree */
	NULL,                        /* ServerSessionEnd */
	NULL,                        /* KeyboardEvent */
	NULL,                        /* MouseEvent */
	NULL,                        /* ClientChannelData */
	NULL,                        /* ServerChannelData */
};

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
	g_plugins_manager = plugins_manager;

	return plugins_manager->RegisterPlugin(&demo_plugin);
}
