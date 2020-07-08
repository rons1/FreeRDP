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
#include <sstream>
#include <ctime>
#include <chrono>

#include <winpr/winsock.h>
#include "modules_api.h"
#include "pf_config.h"

#define TAG MODULE_TAG("input_events_logger")

static constexpr char plugin_name[] = "demo";
static constexpr char plugin_desc[] = "this is a test plugin";

static proxyPluginsManager* g_plugins_manager = NULL;
static SOCKET sock = -1;
static struct sockaddr_in servaddr;

#define KBD_EVENT 0
#define MOUSE_EVENT 1

typedef struct plugin_data
{
	HANDLE thread;
	wMessageQueue* queue;
} pluginData;

typedef struct config
{
	UINT16 port;
	char* ip_address;
} pluginConfig;

static pluginConfig config = { 0 };

static BOOL logger_plugin_config_load()
{
	BOOL ok = FALSE;
	wIniFile* ini = IniFile_New();

	if (!ini)
	{
		WLog_ERR(TAG, "logger_plugin_config_load: IniFile_New() failed!");
		return FALSE;
	}

	if (IniFile_ReadFile(ini, "events-logger.ini") < 0)
	{
		WLog_ERR(TAG, "logger_plugin_config_load: IniFile_ReadFile() failed!");
		goto out;
	}

	config.ip_address = _strdup(pf_config_get_str(ini, "EventsLogger", "IpAddress"));
	if (!pf_config_get_uint16(ini, "EventsLogger", "Port", &config.port))
		goto out;

	ok = TRUE;

out:
	IniFile_Free(ini);
	return ok;
}

static INLINE UINT64 get_current_epoch_time()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(
	           std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

static void logger_plugin_send_log_over_udp(std::string& log)
{
	_sendto(sock, log.c_str(), log.length(), 0, (const struct sockaddr*)&servaddr,
	        sizeof(servaddr));
}

static void logger_plugin_log_kbd_event(proxyData* pdata, UINT64 now, UINT16 flags,
                                        UINT16 rdp_scan_code)
{
	std::ostringstream out;
	out << "{\"session_id\": \"" << pdata->session_id << "\", \"timestamp\": " << now
	    << ", \"flags\": " << flags << ", \"rdp_scan_code\": " << rdp_scan_code << "}";

	std::string log = out.str();

	logger_plugin_send_log_over_udp(log);
	// std::cout << log << std::endl;
}

static void logger_plugin_log_mouse_event(proxyData* pdata, UINT64 now, UINT16 flags, UINT16 x,
                                          UINT16 y)
{
	std::ostringstream out;
	out << "{\"session_id\": \"" << pdata->session_id << "\", \"timestamp\": " << now
	    << ", \"flags\": " << flags << ", \"x\": " << x << ", \"y\": " << y << "}";

	std::string log = out.str();

	logger_plugin_send_log_over_udp(log);
	// std::cout << log << std::endl;
}

static DWORD WINAPI logger_plugin_events_handler_thread(LPVOID arg)
{
	proxyData* pdata = static_cast<proxyData*>(arg);
	pluginData* p = static_cast<pluginData*>(g_plugins_manager->GetPluginData(plugin_name, pdata));
	DWORD rc = 0;
	wMessage message;
	UINT64 message_time;

	WLog_INFO(TAG, "events handler thread started");

	while (TRUE)
	{
		if (!MessageQueue_Wait(p->queue))
		{
			WLog_ERR(TAG, "MessageQueue_Wait failed!");
			rc = ERROR_INTERNAL_ERROR;
			break;
		}

		if (!MessageQueue_Peek(p->queue, &message, TRUE))
		{
			WLog_ERR(TAG, "MessageQueue_Peek failed!");
			rc = ERROR_INTERNAL_ERROR;
			break;
		}

		if (message.id == WMQ_QUIT)
			break;

		message_time = (UINT64)message.context;

		switch (message.id)
		{
			case WMQ_QUIT:
			{
				WLog_INFO(TAG, "events handler thread: exiting");
				break;
			}

			case KBD_EVENT:
			{
				UINT16 flags = (UINT16)(UINT64)message.wParam;
				UINT16 rdp_scan_code = (UINT16)(UINT64)message.lParam;
				logger_plugin_log_kbd_event(pdata, message_time, flags, rdp_scan_code);
				break;
			}

			case MOUSE_EVENT:
			{
				UINT16 flags = (UINT16)(UINT64)message.wParam;
				UINT32 pos = (UINT32)(UINT64)message.lParam;
				UINT16 x = ((pos & 0xFFFF0000) >> 16);
				UINT16 y = (pos & 0x0000FFFF);

				logger_plugin_log_mouse_event(pdata, message_time, flags, x, y);
				break;
			}
		}
	}

	ExitThread(rc);
	return rc;
}

static void plugin_data_free(pluginData* pd)
{
	MessageQueue_Free(pd->queue);
	CloseHandle(pd->thread);
	free(pd);
}

static pluginData* plugin_data_new()
{
	pluginData* pd = (pluginData*)calloc(1, sizeof(pluginData));

	pd->queue = MessageQueue_New(NULL);
	if (!pd->queue)
		goto error;

	return pd;
error:
	plugin_data_free(pd);
	return NULL;
}

static BOOL logger_plugin_keyboard_event(proxyData* pdata, void* param)
{
	auto event = static_cast<proxyKeyboardEventInfo*>(param);
	auto pd = static_cast<pluginData*>(g_plugins_manager->GetPluginData(plugin_name, pdata));
	UINT64 now = get_current_epoch_time();

	MessageQueue_Post(pd->queue, (void*)now, KBD_EVENT, (void*)(size_t)event->flags,
	                  (void*)(size_t)event->rdp_scan_code);
	return TRUE;
}

static BOOL logger_plugin_mouse_event(proxyData* pdata, void* param)
{
	auto event = static_cast<proxyMouseEventInfo*>(param);
	auto pd = static_cast<pluginData*>(g_plugins_manager->GetPluginData(plugin_name, pdata));
	UINT64 now = get_current_epoch_time();
	UINT32 pos = (event->x << 16) | event->y;

	MessageQueue_Post(pd->queue, (void*)now, MOUSE_EVENT, (void*)(size_t)event->flags,
	                  (void*)(size_t)pos);
	return TRUE;
}

static BOOL logger_plugin_server_post_connect(proxyData* pdata)
{
	pluginData* p = plugin_data_new();
	if (!p)
		return FALSE;

	g_plugins_manager->SetPluginData(plugin_name, pdata, p);

	if (!(p->thread = CreateThread(NULL, 0, logger_plugin_events_handler_thread, pdata, 0, NULL)))
		return FALSE;

	return TRUE;
}

static BOOL logger_plugin_session_end(proxyData* pdata)
{
	auto pd = static_cast<pluginData*>(g_plugins_manager->GetPluginData(plugin_name, pdata));
	if (!pd)
		return TRUE;

	MessageQueue_PostQuit(pd->queue, 0);

	WLog_INFO(TAG, "closing events thread");
	if (WaitForSingleObject(pd->thread, INFINITE) == WAIT_FAILED)
	{
		DWORD rc = GetLastError();
		WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "", rc);
	}
	WLog_INFO(TAG, "events thread closed");

	plugin_data_free(pd);
	return TRUE;
}

static SOCKET logger_plugin_init_socket()
{
	int status;
	int sockfd;
	struct sockaddr_in addr = { 0 };
	sockfd = _socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd == -1)
		return -1;

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;          /* host byte order */
	servaddr.sin_port = htons(config.port); /* short, network byte order */
	inet_pton(AF_INET, config.ip_address, &(servaddr.sin_addr));
	return sockfd;
}

static BOOL logger_plugin_unload()
{
	/* free config */
	free(config.ip_address);

	closesocket(sock);
	return TRUE;
}

static proxyPlugin demo_plugin = {
	plugin_name,                       /* name */
	plugin_desc,                       /* description */
	logger_plugin_unload,              /* PluginUnload */
	NULL,                              /* ClientPreConnect */
	NULL,                              /* ClientPostConnect */
	NULL,                              /* ClientLoginFailure */
	NULL,                              /* ClientEndPaint */
	logger_plugin_server_post_connect, /* ServerPostConnect */
	NULL,                              /* ServerChannelsInit */
	NULL,                              /* ServerChannelsFree */
	logger_plugin_session_end,         /* ServerSessionEnd */
	logger_plugin_keyboard_event,      /* KeyboardEvent */
	logger_plugin_mouse_event,         /* MouseEvent */
	NULL,                              /* ClientChannelData */
	NULL,                              /* ServerChannelData */
};

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
	g_plugins_manager = plugins_manager;

	if (!logger_plugin_config_load())
		return FALSE;

	sock = logger_plugin_init_socket();
	if (sock == -1)
		return FALSE;

	WLog_INFO(TAG, "Logger plugin is initialized. logs will be sent to %s:%d.", config.ip_address,
	          config.port);
	return plugins_manager->RegisterPlugin(&demo_plugin);
}
