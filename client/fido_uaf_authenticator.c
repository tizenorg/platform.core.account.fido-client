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

#include "fido_internal_types.h"
#include "fido_uaf_authenticator.h"
#include "fido_logs.h"

EXPORT_API int
fido_authenticator_get_title(const fido_authenticator_h auth, char **title)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	RET_IF_FAIL(title != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	RET_IF_FAIL(priv->title != NULL, FIDO_ERROR_INVALID_PARAMETER);

	*title = strdup(priv->title);

	RET_IF_FAIL(title == NULL, FIDO_ERROR_OUT_OF_MEMORY);

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_aaid(const fido_authenticator_h auth, char **aaid)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	RET_IF_FAIL(aaid != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	RET_IF_FAIL(priv->aaid != NULL, FIDO_ERROR_INVALID_PARAMETER);

	*aaid = strdup(priv->aaid);

	RET_IF_FAIL(aaid == NULL, FIDO_ERROR_OUT_OF_MEMORY);

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_description(const fido_authenticator_h auth, char **desc)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	RET_IF_FAIL(desc != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	RET_IF_FAIL(priv->description != NULL, FIDO_ERROR_INVALID_PARAMETER);

	*desc = strdup(priv->description);

	RET_IF_FAIL(desc == NULL, FIDO_ERROR_OUT_OF_MEMORY);

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_assertion_scheme(const fido_authenticator_h auth, char **scheme)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	RET_IF_FAIL(scheme != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	RET_IF_FAIL(priv->assertion_scheme != NULL, FIDO_ERROR_INVALID_PARAMETER);

	*scheme = strdup(priv->assertion_scheme);

	RET_IF_FAIL(scheme == NULL, FIDO_ERROR_OUT_OF_MEMORY);

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_algorithm(const fido_authenticator_h auth, fido_auth_algo_e *algo)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	*algo = priv->authentication_algorithm;

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_foreach_attestation_type(const fido_authenticator_h auth, fido_attestation_type_cb cb,
void *user_data)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	if (priv->attestation_types == NULL
		|| g_list_length(priv->attestation_types) <= 0)
		return FIDO_ERROR_NO_DATA;

	GList *list_iter = g_list_first(priv->attestation_types);
	while (list_iter != NULL) {
		int att_type = GPOINTER_TO_INT(list_iter->data);

		(cb)(att_type, user_data);

		list_iter = list_iter->next;
	}

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_verification_method(const fido_authenticator_h auth, fido_auth_user_verify_type_e *user_verification)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	*user_verification = priv->user_verification;

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_key_protection_method(const fido_authenticator_h auth, fido_auth_key_protection_type_e *key_protection)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	*key_protection = priv->key_protection;

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_matcher_protection_method(const fido_authenticator_h auth, fido_auth_matcher_protection_type_e *matcher_protection)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	*matcher_protection = priv->matcher_protection;

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_attachment_hint(const fido_authenticator_h auth, fido_auth_attachment_hint_e *attachment_hint)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	*attachment_hint = priv->attachment_hint;

	return FIDO_ERROR_NONE;
}

EXPORT_API bool
fido_authenticator_get_is_second_factor_only(const fido_authenticator_h auth)
{
	RET_IF_FAIL(auth != NULL, false);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	return priv->is_second_factor_only;
}

EXPORT_API int
fido_authenticator_get_tc_discplay(const fido_authenticator_h auth, fido_auth_tc_display_type_e *tc_display)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	*tc_display = priv->tc_display;

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_tc_display_type(const fido_authenticator_h auth, char **tc_display_content_type)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	RET_IF_FAIL(tc_display_content_type != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	RET_IF_FAIL(priv->tc_display_content_type != NULL, FIDO_ERROR_INVALID_PARAMETER);

	*tc_display_content_type = strdup(priv->tc_display_content_type);

	RET_IF_FAIL(tc_display_content_type == NULL, FIDO_ERROR_OUT_OF_MEMORY);

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_authenticator_get_icon(const fido_authenticator_h auth, char **icon)
{
	RET_IF_FAIL(auth != NULL, FIDO_ERROR_INVALID_PARAMETER);

	RET_IF_FAIL(icon != NULL, FIDO_ERROR_INVALID_PARAMETER);

	fido_authenticator_s *priv = (fido_authenticator_s*)auth;

	RET_IF_FAIL(priv->icon != NULL, FIDO_ERROR_INVALID_PARAMETER);

	*icon = strdup(priv->icon);

	RET_IF_FAIL(icon == NULL, FIDO_ERROR_OUT_OF_MEMORY);

	return FIDO_ERROR_NONE;
}

