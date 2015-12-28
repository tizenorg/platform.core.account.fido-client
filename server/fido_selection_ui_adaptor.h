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

#ifndef FIDO_SELECTION_UI_ADAPTOR_H
#define FIDO_SELECTION_UI_ADAPTOR_H

#include <tizen.h>
#include <glib.h>
#include "fido-stub.h"
#include "fido_internal_types.h"

gboolean _auth_ui_selector_on_ui_response(Fido *object, GDBusMethodInvocation *invocation, int error, const char *ui_resp);

typedef void (*_ui_response_cb) (int eror_code, _ui_auth_data_t *selected_auth_data, void *user_data);
int _auth_ui_selector_send(GList *auth_list, _ui_response_cb cb, void *user_data);

#endif // FIDO_SELECTION_UI_ADAPTOR_H
