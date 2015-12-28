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

#ifndef __FIDO_APP_ID_HANDLER_H__
#define __FIDO_APP_ID_HANDLER_H__

#include <tizen.h>
#include <gio/gio.h>

typedef void (*_facet_id_cb) (int eror_code, const char *facet_id, void *user_data);

int _verify_and_get_facet_id(const char *uaf_app_id, GDBusMethodInvocation *invocation, _facet_id_cb cb, void *user_data);

#endif /* __FIDO_APP_ID_HANDLER_H__ */
