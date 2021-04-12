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
#include <memory>
#include <spdlog/spdlog.h>

#include "modules_api.h"

#define TAG MODULE_TAG("demo")

static constexpr char plugin_name[] = "events-logger";
static constexpr char plugin_desc[] = "send mouse and clipboard data";

static proxyPluginsManager* g_plugins_manager = NULL;

enum severity
{
	debug = 0,
	info = 1,
	warn = 2,
	error = 3
};

static BOOL log_msg(const wLogMessage* msg, const char* session_id)
{
	if (!msg)
		return FALSE;

	if (!session_id)
	{
		switch (msg->Level)
		{
			case WLOG_INFO:
				spdlog::info("{}", msg->TextString);
				break;
			case WLOG_ERROR:
				spdlog::warn("{}", msg->TextString);
				break;
			case WLOG_DEBUG:
				spdlog::debug("{}", msg->TextString);
				break;
			case WLOG_WARN:
				spdlog::warn("{}", msg->TextString);
				break;
			default:
				return TRUE;
		}
	}
	else
	{
		switch (msg->Level)
		{
			case WLOG_INFO:
				spdlog::info("[{}] {}", session_id, msg->TextString);
				break;
			case WLOG_ERROR:
				spdlog::warn("[{}] {}", session_id, msg->TextString);
				break;
			case WLOG_DEBUG:
				spdlog::debug("[{}] {}", session_id, msg->TextString);
				break;
			case WLOG_WARN:
				spdlog::warn("[{}] {}", session_id, msg->TextString);
				break;
			default:
				return TRUE;
		}
	}

	return TRUE;
}

static proxyPlugin demo_plugin = {
	plugin_name, /* name */
	plugin_desc, /* description */
	NULL,        /* PluginUnload */
	NULL,        /* ClientPreConnect */
	NULL,        /* ClientPostConnect */
	NULL,        /* ClientLoginFailure */
	NULL,        /* ClientEndPaint */
	NULL,        /* ServerPostConnect */
	NULL,        /* ServerChannelsInit */
	NULL,        /* ServerChannelsFree */
	NULL,        /* ServerSessionEnd */
	NULL,        /* KeyboardEvent */
	NULL,        /* MouseEvent */
	NULL,        /* ClientChannelData */
	NULL,        /* ServerChannelData */
	log_msg,     /* log */
};

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
	g_plugins_manager = plugins_manager;
	return plugins_manager->RegisterPlugin(&demo_plugin);
}
