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

#include <string.h>
#include <stdlib.h>
#include "fido_logs.h"
#include "fido_internal_types.h"

void
_free_extension(_extension_t *data)
{
	_INFO("");

	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->id);
	SAFE_DELETE(data->data);
	SAFE_DELETE(data);
	_INFO("");
}

static void
_free_extension_list_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_extension((_extension_t*)data);
	_INFO("");
}

void
_free_match_criteria(_match_criteria_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	if (data->aaid_list != NULL)
		g_list_free_full(data->aaid_list, free);

	if (data->vendor_list != NULL)
		g_list_free_full(data->vendor_list, free);

	if (data->key_id_list != NULL)
		g_list_free_full(data->key_id_list, free);

	if (data->auth_algo_list != NULL)
		g_list_free(data->auth_algo_list);

	if (data->assertion_scheme_list != NULL)
		g_list_free_full(data->assertion_scheme_list, free);

	if (data->attestation_type_list != NULL)
		g_list_free_full(data->attestation_type_list, free);

	if (data->extension_list != NULL)
		g_list_free_full(data->extension_list, _free_extension_list_item);

	SAFE_DELETE(data);
	_INFO("");
}

static void
_free_uaf_accepted_list_inner_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_match_criteria((_match_criteria_t*)data);
	_INFO("");
}

static void
_free_uaf_accepted_list_outer_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	GList *list = (GList*)data;
	if (list != NULL)
		g_list_free_full(list, _free_uaf_accepted_list_inner_item);
	_INFO("");
}

static void
_free_uaf_disallowed_list_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_match_criteria((_match_criteria_t*)data);
	_INFO("");
}

void
_free_policy(_policy_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	if (data->accepted_list != NULL)
		g_list_free_full(data->accepted_list, _free_uaf_accepted_list_outer_item);

	if (data->disallowed_list != NULL)
		g_list_free_full(data->disallowed_list, _free_uaf_disallowed_list_item);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_op_header(_op_header_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->version);
	SAFE_DELETE(data->operation);
	SAFE_DELETE(data->app_id);
	SAFE_DELETE(data->server_data);

	if (data->ext_list != NULL)
		g_list_free_full(data->ext_list, _free_extension_list_item);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_message(_message_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->facet_id);

	_free_op_header(data->header);

	SAFE_DELETE(data->channel_binding);

	switch (data->type) {

	case _MESSAGE_TYPE_REG:
		_free_reg_request((_reg_request_t*)(data->data));
		break;

	case _MESSAGE_TYPE_AUTH:
		_free_auth_request((_auth_request_t*)(data->data));
		break;

	case _MESSAGE_TYPE_DEREG:
		_free_dereg_request((_dereg_request_t*)(data->data));
		break;

	default:
		SAFE_DELETE(data->data);
	}

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_reg_request(_reg_request_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->challenge);
	SAFE_DELETE(data->user_name);

	_free_policy(data->policy);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_display_png_characteristics_descriptor(fido_display_png_characteristics_descriptor_s *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	if (data->plte != NULL)
		g_list_free_full(data->plte, free);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_auth_transaction(_auth_transaction_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->content);
	SAFE_DELETE(data->content_type);

	_free_display_png_characteristics_descriptor(data->display_charac);

	SAFE_DELETE(data);
	_INFO("");
}

static void
__free_auth_transaction_list_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_auth_transaction((_auth_transaction_t*)data);
	_INFO("");
}

void
_free_auth_request(_auth_request_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->challenge);

	_free_policy(data->policy);

	if (data->transaction_list != NULL)
		g_list_free_full(data->transaction_list, __free_auth_transaction_list_item);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_dereg_auth_info(_dereg_auth_info_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->aaid);
	SAFE_DELETE(data->key_id);
	SAFE_DELETE(data);
	_INFO("");
}

static void
__free_dereg_auth_info_list_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_dereg_auth_info((_dereg_auth_info_t*)data);
	_INFO("");
}

void
_free_dereg_request(_dereg_request_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	if (data->auth_info_list != NULL)
		g_list_free_full(data->auth_info_list, __free_dereg_auth_info_list_item);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_asm_display_png_characteristics_descriptor_t(_fido_asm_display_png_characteristics_descriptor_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	if (data->plte != NULL)
		g_list_free_full(data->plte, free);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_fido_asm_proxy(void *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_fido_asm_proxy_t *data_impl = (_fido_asm_proxy_t*)data;
	SAFE_DELETE(data_impl->asm_id);
	SAFE_DELETE(data_impl->vendor);
	SAFE_DELETE(data_impl->bin_path);
	SAFE_DELETE(data_impl->dbus_info);
	SAFE_DELETE(data_impl->dbus_obj_path);
	SAFE_DELETE(data_impl->dbus_interface_name);
	SAFE_DELETE(data_impl->dbus_method_name);

	g_object_unref(data_impl->dbus_proxy);

	SAFE_DELETE(data_impl);

	_INFO("");
}

void
_free_asm_discover_response(_asm_discover_response_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->asm_id);
	SAFE_DELETE(data->asm_response_json);
	SAFE_DELETE(data);
	_INFO("");
}

void
_free_fido_asm_authenticator(fido_authenticator_s *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->asm_id);

	_INFO("");

	SAFE_DELETE(data->auth_index);

	_INFO("");

	if (data->key_ids != NULL)
		g_list_free_full(data->key_ids, free);
	_INFO("");

	/*TODO : asm_versions is not used anywhere*/

	SAFE_DELETE(data->aaid);
	_INFO("");

	SAFE_DELETE(data->assertion_scheme);
	_INFO("");

	if (data->attestation_types != NULL)
		g_list_free(data->attestation_types);
	_INFO("");

	if (data->supported_extension_IDs != NULL)
		g_list_free_full(data->supported_extension_IDs, free);
	_INFO("");

	SAFE_DELETE(data->tc_display_content_type);
	_INFO("");

	if (data->tc_display_png_characteristics != NULL)
		g_list_free_full(data->tc_display_png_characteristics, _free_tc_disp_png_char);
	_INFO("");

	SAFE_DELETE(data->title);
	_INFO("");

	SAFE_DELETE(data->description);
	_INFO("");

	SAFE_DELETE(data->icon);
	_INFO("");

	if (data->supported_versions != NULL)
		g_list_free_full(data->supported_versions, free);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_fido_asm_authenticator_list_item(gpointer data)
{
	RET_IF_FAIL_VOID(data != NULL);

	fido_authenticator_s *data_impl = (fido_authenticator_s*)data;

	_free_fido_asm_authenticator(data_impl);
}

void
_free_fido_asm_reg_in(_fido_asm_reg_in_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->app_id);
	SAFE_DELETE(data->user_name);
	SAFE_DELETE(data->final_challenge);
	SAFE_DELETE(data);
	_INFO("");
}

void
_free_fido_asm_transaction(_fido_asm_transaction_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->content);
	SAFE_DELETE(data->content_type);
	_free_asm_display_png_characteristics_descriptor_t(data->display_charac);
	SAFE_DELETE(data);
	_INFO("");
}

static void
__free_fido_asm_transaction_list_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_fido_asm_transaction((_fido_asm_transaction_t *)data);
	_INFO("");
}

void
_free_fido_asm_auth_in(_fido_asm_auth_in_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->app_id);
	SAFE_DELETE(data->final_challenge);
	if (data->key_ids != NULL)
		g_list_free_full(data->key_ids, free);

	if (data->trans_list != NULL)
		g_list_free_full(data->trans_list, __free_fido_asm_transaction_list_item);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_fido_asm_dereg_in(_fido_asm_dereg_in_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->app_id);
	SAFE_DELETE(data->key_id);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_ui_auth_data(_ui_auth_data_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->asm_id);
	SAFE_DELETE(data->auth_index);
	SAFE_DELETE(data->label);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_auth_reg_assertion(_auth_reg_assertion_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->assertion_schm);
	SAFE_DELETE(data->assertion);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_auth_reg_assertion_list_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_auth_reg_assertion((_auth_reg_assertion_t*)data);
	_INFO("");
}

void
_free_asm_out(_asm_out_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	switch (data->type) {

	case _ASM_OUT_TYPE_REG:
		_free_asm_reg_out((_asm_reg_out_t*)(data->response_data));
		break;

	case _ASM_OUT_TYPE_AUTH:
		_free_asm_auth_out((_asm_auth_out_t*)(data->response_data));
		break;

	default:
		SAFE_DELETE(data->response_data);
	}

	if (data->ext_list != NULL) {
		_INFO("Freeing ext list");
		g_list_free_full(data->ext_list, free);
		_INFO("After Freeing ext list");
	}

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_asm_reg_out(_asm_reg_out_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->assertion);
	SAFE_DELETE(data->assertion_schm);
	SAFE_DELETE(data);
	_INFO("");
}

void
_free_asm_auth_out(_asm_auth_out_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->assertion);
	SAFE_DELETE(data->assertion_scheme);
	SAFE_DELETE(data);
	_INFO("");
}

void
_free_tlv(_tlv_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->val);
	SAFE_DELETE(data);

	_INFO("");
}

void
_free_tc_disp_png_char(gpointer data)
{
	_INFO("");
	if (data == NULL)
		return;

	fido_display_png_characteristics_descriptor_s *png = (fido_display_png_characteristics_descriptor_s*)data;
	if (png->plte != NULL)
		g_list_free_full(png->plte, free);

	SAFE_DELETE(png);
	_INFO("");
}

void
_free_asm_auth_list(gpointer data)
{
	_INFO("_free_asm_auth_list start");

	if (data == NULL)
		return;

	_free_fido_asm_authenticator((fido_authenticator_s*)data);

	_INFO("_free_asm_auth_list end");

}

void
_free_matched_auth_dereg(_matched_auth_dereg_t *data)
{
	_INFO("_free_matched_auth_dereg start");
	if (data == NULL)
		return;

	SAFE_DELETE(data->asm_id);
	SAFE_DELETE(data->auth_index);
	SAFE_DELETE(data->app_id);
	SAFE_DELETE(data->key_id);

	SAFE_DELETE(data);
	_INFO("_free_matched_auth_dereg end");
}

void
_free_asm_app_reg(_asm_app_reg_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->app_id);

	if (data->key_id_list != NULL)
		g_list_free_full(data->key_id_list, free);

	SAFE_DELETE(data);
	_INFO("");
}

static void
__free_asm_app_reg_list_item(gpointer data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_asm_app_reg((_asm_app_reg_t*)data);
	_INFO("");
}

void
_free_asm_get_reg_out(_asm_get_reg_out_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	if (data->app_reg_list != NULL)
		g_list_free_full(data->app_reg_list, __free_asm_app_reg_list_item);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_auth_reg_assertion_tlv(_auth_reg_assertion_tlv_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	SAFE_DELETE(data->aaid);
	SAFE_DELETE(data->key_id);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_response(_response_t *data)
{
	_INFO("");
	RET_IF_FAIL_VOID(data != NULL);

	_free_op_header(data->header);
	SAFE_DELETE(data->fcp);

	if (data->assertion_list != NULL)
		g_list_free_full(data->assertion_list, _free_auth_reg_assertion_list_item);

	SAFE_DELETE(data);
	_INFO("");
}

void
_free_matched_auth_data(gpointer data)
{
	_INFO("_free_matched_auth_data start");
	if (data == NULL)
		return;

	_matched_auth_data_t *match_auth_data = (_matched_auth_data_t*)data;

	SAFE_DELETE(match_auth_data->asm_id);
	SAFE_DELETE(match_auth_data->auth_index);
	SAFE_DELETE(match_auth_data->label);
	SAFE_DELETE(match_auth_data);

	_INFO("_free_matched_auth_data end");
}
