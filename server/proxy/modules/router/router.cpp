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

#define TAG MODULE_TAG("router")

static constexpr char plugin_name[] = "router";
static constexpr char plugin_desc[] = "routes tsv:// to broker and other request by explicit ip";

static proxyPluginsManager* g_plugins_manager = NULL;

static BOOL router_server_fetch_target_addr(proxyData* pdata, void* param)
{
	auto ev = static_cast<proxyFetchTargetEventInfo*>(param);
	if (pdata == NULL || ev == NULL)
		return FALSE;

	rdpContext* context = &pdata->ps->context;
	DWORD routing_token_length;
	const char* tmp = freerdp_nego_get_routing_token(context, &routing_token_length);

	std::string lbinfo(tmp, routing_token_length);
	if (lbinfo.find("tsv://") != std::string::npos)
		ev->fetch_method = PROXY_FETCH_TARGET_METHOD_CONFIG;
	else
		ev->fetch_method = PROXY_FETCH_TARGET_METHOD_LOAD_BALANCE_INFO;

	return TRUE;
}

static proxyPlugin router_plugin = {
	plugin_name,                    /* name */
	plugin_desc,                    /* description */
	NULL,                           /* PluginUnload */
	NULL,                           /* ClientPreConnect */
	NULL,                           /* ClientPostConnect */
	NULL,                           /* ClientLoginFailure */
	NULL,                           /* ClientEndPaint */
	NULL,                           /* ServerPostConnect */
	NULL,                           /* ServerChannelsInit */
	NULL,                           /* ServerChannelsFree */
	NULL,                           /* ServerSessionEnd */
	NULL,                           /* KeyboardEvent */
	NULL,                           /* MouseEvent */
	NULL,                           /* ClientChannelData */
	NULL,                           /* ServerChannelData */
	router_server_fetch_target_addr /* ServerFetchTargetAddr */
};

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
	g_plugins_manager = plugins_manager;

	return plugins_manager->RegisterPlugin(&router_plugin);
}
