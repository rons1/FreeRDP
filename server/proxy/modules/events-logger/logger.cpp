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
#include <cinttypes>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <libpq-fe.h>
#include <winpr/winsock.h>

#include "modules_api.h"
#include "pf_config.h"

#define TAG MODULE_TAG("input_events_logger")

static constexpr char plugin_name[] = "events logger";
static constexpr char plugin_desc[] = "logs mouse events to postgres";

static proxyPluginsManager* g_plugins_manager = NULL;
static SOCKET sock = -1;
static struct sockaddr_in servaddr;

static PGconn* g_conn = NULL;
static wMessageQueue* g_queue;
static HANDLE g_processor_thread = NULL;
static int g_count = 0;
std::string g_insert_query = "";

#define KBD_EVENT 0
#define MOUSE_EVENT 1

typedef struct config
{
	UINT16 port;
	char* ip_address;
} pluginConfig;

static pluginConfig config = { 0 };
static BOOL logger_plugin_insert_event_to_postgres(proxyData* pdata, UINT64 now, UINT16 flags,
                                                   UINT16 x, UINT16 y);

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
}

static void logger_plugin_log_mouse_event(proxyData* pdata, UINT64 now, UINT16 flags, UINT16 x,
                                          UINT16 y)
{
	std::ostringstream out;
	out << "{\"session_id\": \"" << pdata->session_id << "\", \"timestamp\": " << now
	    << ", \"flags\": " << flags << ", \"x\": " << x << ", \"y\": " << y << "}";

	std::string log = out.str();

	logger_plugin_send_log_over_udp(log);
	logger_plugin_insert_event_to_postgres(pdata, now, flags, x, y);
}

static DWORD WINAPI logger_plugin_events_handler_thread(LPVOID arg)
{
	DWORD rc = 0;
	wMessage message;
	UINT64 message_time;
	proxyData* pdata;

	WLog_INFO(TAG, "events handler thread started");

	while (TRUE)
	{
		if (!MessageQueue_Wait(g_queue))
		{
			WLog_ERR(TAG, "MessageQueue_Wait failed!");
			rc = ERROR_INTERNAL_ERROR;
			break;
		}

		if (!MessageQueue_Peek(g_queue, &message, TRUE))
		{
			WLog_ERR(TAG, "MessageQueue_Peek failed!");
			rc = ERROR_INTERNAL_ERROR;
			break;
		}

		if (message.id == WMQ_QUIT)
			break;

		UINT64 now = get_current_epoch_time();
		pdata = (proxyData*)message.context;

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
				logger_plugin_log_kbd_event(pdata, now, flags, rdp_scan_code);
				break;
			}

			case MOUSE_EVENT:
			{
				UINT16 flags = (UINT16)(UINT64)message.wParam;
				UINT32 pos = (UINT32)(UINT64)message.lParam;
				UINT16 x = ((pos & 0xFFFF0000) >> 16);
				UINT16 y = (pos & 0x0000FFFF);
				pdata = (proxyData*)message.context;

				logger_plugin_log_mouse_event(pdata, now, flags, x, y);
				break;
			}
		}
	}

	ExitThread(rc);
	return rc;
}

static BOOL logger_plugin_keyboard_event(proxyData* pdata, void* param)
{
	auto event = static_cast<proxyKeyboardEventInfo*>(param);
	MessageQueue_Post(g_queue, (void*)pdata, KBD_EVENT, (void*)(size_t)event->flags,
	                  (void*)(size_t)event->rdp_scan_code);
	return TRUE;
}

static BOOL logger_plugin_mouse_event(proxyData* pdata, void* param)
{
	auto event = static_cast<proxyMouseEventInfo*>(param);
	UINT32 pos = (event->x << 16) | event->y;

	MessageQueue_Post(g_queue, (void*)pdata, MOUSE_EVENT, (void*)(size_t)event->flags,
	                  (void*)(size_t)pos);
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

	MessageQueue_PostQuit(g_queue, 0);

	WLog_INFO(TAG, "closing events thread");
	if (WaitForSingleObject(g_processor_thread, INFINITE) == WAIT_FAILED)
	{
		DWORD rc = GetLastError();
		WLog_WARN(TAG, "WaitForSingleObject failed with error %" PRIu32 "", rc);
	}

	WLog_INFO(TAG, "events thread closed");

	if (g_count > 0)
	{
		// Insert last batch of logs to database.
		PGresult* res = PQexec(g_conn, g_insert_query.c_str());
		WLog_INFO(TAG, "Executing batch: inserting last batch of %d rows", g_count);
	
		if (PQresultStatus(res) != PGRES_COMMAND_OK)
			WLog_ERR(TAG, "couldn't insert row to databse, error code: 0x%x\n", PQresultStatus(res));

		PQclear(res);
		g_count = 0;
		g_insert_query = "";
	}

	closesocket(sock);
	MessageQueue_Free(g_queue);
	PQfinish(g_conn);
	CloseHandle(g_processor_thread);
	return TRUE;
}

static proxyPlugin demo_plugin = {
	plugin_name,                  /* name */
	plugin_desc,                  /* description */
	logger_plugin_unload,         /* PluginUnload */
	NULL,                         /* ClientPreConnect */
	NULL,                         /* ClientPostConnect */
	NULL,                         /* ClientLoginFailure */
	NULL,                         /* ClientEndPaint */
	NULL,                         /* ServerPostConnect */
	NULL,                         /* ServerChannelsInit */
	NULL,                         /* ServerChannelsFree */
	NULL,                         /* ServerSessionEnd */
	logger_plugin_keyboard_event, /* KeyboardEvent */
	logger_plugin_mouse_event,    /* MouseEvent */
	NULL,                         /* ClientChannelData */
	NULL,                         /* ServerChannelData */
};

static BOOL logger_plugin_insert_event_to_postgres(proxyData* pdata, UINT64 now, UINT16 flags,
                                                   UINT16 x, UINT16 y)
{
	std::ostringstream ss;
	ss << "INSERT INTO playground (time, sessionid, flags, scancode, x, y, username) VALUES(" << now
	   << ",'" << pdata->session_id << "'," << flags << "," << 0 << "," << x << "," << y << ",'"
	   << pdata->pc->context.settings->Username << "');";
	g_insert_query.append(ss.str());

	if (g_count == 1000)
	{
		PGresult* res = PQexec(g_conn, g_insert_query.c_str());
		WLog_INFO(TAG, "Executing batch: inserting 1000 rows");

		if (PQresultStatus(res) != PGRES_COMMAND_OK)
		{
			WLog_ERR(TAG, "couldn't insert row to databse, error code: 0x%x\n",
			         PQresultStatus(res));
			PQclear(res);
			return FALSE;
		}

		WLog_INFO(TAG, "reset batch count");
		g_insert_query = "";
		g_count = 0;
		PQclear(res);
	}

	WLog_DBG(TAG, "row %d: adding to next batch", g_count);
	g_count++;
	return TRUE;
}

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
	g_plugins_manager = plugins_manager;

	if (!logger_plugin_config_load())
		return FALSE;

	sock = logger_plugin_init_socket();
	if (sock == -1)
		return FALSE;

	g_queue = MessageQueue_New(NULL);
	if (!(g_processor_thread =
	          CreateThread(NULL, 0, logger_plugin_events_handler_thread, NULL, 0, NULL)))
		return FALSE;

	WLog_INFO(TAG, "Logger plugin is initialized. logs will be sent to %s:%d.", config.ip_address,
	          config.port);
	// Connect to PostgRES.
	g_conn = PQconnectdb("user=kobi password=Dadush1020304050 dbname=plex");
	if (PQstatus(g_conn) == CONNECTION_BAD)
	{
		fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(g_conn));
	}
	return plugins_manager->RegisterPlugin(&demo_plugin);
}

