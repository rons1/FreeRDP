/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Proxy Server
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

#include <hiredis/hiredis.h>

#include "modules_api.h"
#include "pf_context.h"
#include "pf_log.h"

#define TAG PROXY_TAG("modules.firewall")

static redisContext* redis_conn = NULL;

static BOOL firewall_client_pre_connect(moduleOperations* module, rdpContext* context)
{
	BOOL ok = FALSE;
	redisReply* reply;
	pServerContext* ps = (pServerContext*)context;
	pClientContext* pc = ps->pdata->pc;
	size_t index;
	const char* username = context->settings->Username;
	const char* remote_host = pc->context.settings->ServerHostname;
	size_t target_host_len = strlen(remote_host);

	/* query redis with username */
	reply = redisCommand(redis_conn, "LRANGE %s 0 -1", username);
	if (reply == NULL)
	{
		WLog_ERR(TAG, "failed to GET data from redis");
		return FALSE;
	}

	if (reply->type != REDIS_REPLY_ARRAY)
		goto fail;

	/* check if the target hostname is in user's whitelist */
	for (index = 0; index < reply->elements; index++)
	{
		redisReply* nested_reply = reply->element[index];

		if (nested_reply->type != REDIS_REPLY_STRING)
		{
			WLog_ERR(TAG, "expected string, got %d", nested_reply->type);
			goto fail;
		}

		if (nested_reply->len != target_host_len)
			continue;

		if (strcmp(nested_reply->str, remote_host) == 0)
		{
			ok = TRUE;
			break;
		}
	}

fail:
	freeReplyObject(reply);

	if (!ok)
		WLog_ERR(TAG, "username %s is not allowed to connect to %s", username, remote_host);
	return ok;
}

BOOL module_init(moduleOperations* module)
{
	module->ClientPreConnect = firewall_client_pre_connect;

	/* initialize redis connection */
	redis_conn = redisConnect("127.0.0.1", 8000);
	if (!redis_conn)
	{
		WLog_ERR(TAG, "failed to establish connection to redis server");
		return FALSE;
	}

	WLog_INFO(TAG, "established connection to redis server");
	return TRUE;
}

BOOL module_exit(moduleOperations* module)
{
	redisFree(redis_conn);
	return TRUE;
}
