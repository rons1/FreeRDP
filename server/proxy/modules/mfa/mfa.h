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

#include "modules_api.h"
#include "pf_log.h"
#include "pf_config.h"
#include "token_validator.h"
#include "pf_context.h"

#include <freerdp/server/mfa.h>

#define PLUGIN_NAME "mfa"
#define PLUGIN_DESC "multi factor authentication over RDP"

#define TAG PROXY_TAG("mfa")

typedef struct mfa_module_config
{
	char* mfa_adfs_base_url;
	char* mfa_audience;
	BOOL insecure_ssl;
	UINT32 token_skew_minutes;
	UINT32 auth_timeout_sec;
	UINT32 refresh_token_interval;
} mfaConfig;

typedef struct mfa_session
{
	proxyData* pdata;
	HANDLE idle_timer; /* timer used to refresh token  */
	HANDLE auth;       /* a manual reset event, which is set when session is authenticated */
} mfaSession;
