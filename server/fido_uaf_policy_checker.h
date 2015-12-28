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

#ifndef FIDO_UAF_POLICY_CHECKER_H
#define FIDO_UAF_POLICY_CHECKER_H

#include <tizen.h>
#include <glib.h>
#include "fido_json_handler.h"
#include "fido_internal_types.h"

bool _policy_checker_is_matched(_match_criteria_t *match_criteria, fido_authenticator_s *auth_info);

/* Returns _matched_auth_data_t list*/
GList * _policy_checker_get_matched_auth_list(_policy_t *policy, GList *auth_list);

/* Returns _matched_auth_dereg_t list*/
GList * _policy_checker_get_matched_auth_list_dereg(const char *app_id, GList *input_auth_list, GList *available_auth_list);

#endif // FIDO_UAF_POLICY_CHECKER_H
