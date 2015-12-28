/*
 * Copyright (c) 2014 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __FIDO_ASM_PLUGIN_MGR_H__
#define __FIDO_ASM_PLUGIN_MGR_H__

#include <glib.h>
#include <tizen.h>
#include "fido_internal_types.h"

int _asm_plugin_mgr_init(void);

void _asm_plugin_mgr_destroy(void);

/*List of _asm_discover_response_t*/
typedef void (*_asm_plugin_discover_response_cb) (GList *asm_disc_resp_list, void * user_data);
int _asm_plugin_mgr_discover_all(_asm_plugin_discover_response_cb cb, void *user_data);

typedef void (*_asm_ipc_response_cb) (int eror_code, const char *asm_response_json, void * user_data);

int _asm_ipc_send(const char *asm_id, const char *asm_request, _asm_ipc_response_cb cb, void *user_data);

char *_asm_ipc_send_sync(const char *asm_id, const char *asm_req);

#endif /* __FIDO_ASM_PLUGIN_MGR_H__ */
