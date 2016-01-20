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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <glib.h>
#if !GLIB_CHECK_VERSION (2, 31, 0)
#include <glib/gmacros.h>
#endif

#include "fido_privilege_checker.h"
#include "fido_asm_plugin_manager.h"
#include "fido_internal_types.h"
#include "fido_json_handler.h"
#include "fido_keys.h"
#include "fido_app_id_handler.h"
#include "fido_uaf_policy_checker.h"
#include "fido_selection_ui_adaptor.h"
#include "fido_logs.h"
#include "fido_uaf_types.h"
#include "fido-stub.h"

#define _FIDO_SERVICE_DBUS_PATH       "/org/tizen/fido"
static guint owner_id = 0;
//GDBusObjectManagerServer *fido_dbus_mgr = NULL;
static Fido* fido_dbus_obj = NULL;

//TODO : current assumption is, ASM will handle multiple request queueing

typedef struct _dbus_info{
	Fido *dbus_obj;
	GDBusMethodInvocation *invocation;
}_dbus_info_t;

typedef struct _discover_cb {
	//fido_authenticator_cb cb;
	void *user_data;
	_dbus_info_t *dbus_info;
} discover_cb_t;

typedef struct _fido_discover_asm_cb_data {
	_fido_discover_asm_cb cb;
	void *user_data;
}_fido_discover_asm_cb_data_t;

typedef enum {
	_PROCESS_TYPE_MIN = 0,
	_PROCESS_TYPE_AUTH,
	_PROCESS_TYPE_REG,
	_PROCESS_TYPE_DEREG,
	_PROCESS_TYPE_CHECK_POLICY,
	_PROCESS_TYPE_MAX
} _process_type_t;

typedef struct _process_cb_data {
	_process_type_t type;
	_message_t *uaf_req;
	void *asm_in;/* ASM input data, type varies depending on operation name */
	_dbus_info_t *dbus_info;
} _process_cb_data_t;

static void __process_dereg_queue(_dereg_q_t *dereg_q);

static char**
__create_empty_json_2d_array(void)
{
	char **asm_resp_json_arr = calloc(1, sizeof(int));

	char *empty_asm_resp = calloc(1, 128);
	snprintf(empty_asm_resp, 127, "%s", _EMPTY_JSON_STRING);
	asm_resp_json_arr[0] = empty_asm_resp;

	return asm_resp_json_arr;
}

static void
__free_2d_string_array(char **arr, int row_count)
{
	RET_IF_FAIL_VOID(arr != NULL);

	int i = 0;
	for (; i < row_count; i++)
		SAFE_DELETE(arr[i]);

	SAFE_DELETE(arr);
}

static char*
__dup_string(const char *source)
{
	if (source != NULL)
		return strdup(source);

	return NULL;
}

static void
__free_asm_discover_response_list_item(gpointer data)
{
	RET_IF_FAIL_VOID(data != NULL);

	_free_asm_discover_response((_asm_discover_response_t*)data);
}

static void
__send_discover_response(Fido *object, GDBusMethodInvocation *invocation, int err, char **asm_resp_2d_arr, int asm_resp_len)
{
	if (asm_resp_2d_arr == NULL
			|| asm_resp_len <= 0) {

		char **empty_arr = __create_empty_json_2d_array();
		fido_complete_fido_uaf_discover(object, invocation, err,
										(const gchar * const*)empty_arr, 0);

		__free_2d_string_array(empty_arr, 1);
		return;
	}

	fido_complete_fido_uaf_discover(object, invocation, err,
									(const gchar * const*)asm_resp_2d_arr, asm_resp_len);

	__free_2d_string_array(asm_resp_2d_arr, asm_resp_len);
}

void
_asm_get_info_cb(GList *asm_resp_list, void *user_data)
{
	_INFO("_asm_get_info_cb");

	_dbus_info_t *dbus_info = (_dbus_info_t *)user_data;
	if (dbus_info != NULL) {

		if (asm_resp_list != NULL) {

			int str_list_len = g_list_length(asm_resp_list);
			char **asm_resp_json_arr = calloc(str_list_len, sizeof(int));
			int data_len = 0;
			int i = 0;

			GList *asm_resp_list_iter = g_list_first(asm_resp_list);
			while (asm_resp_list_iter != NULL) {
				_asm_discover_response_t *disc_resp = (_asm_discover_response_t*)(asm_resp_list_iter->data);

				if (disc_resp->asm_response_json != NULL) {
					asm_resp_json_arr[i++] = strdup(disc_resp->asm_response_json);
					data_len++;
				}
				asm_resp_list_iter = g_list_next(asm_resp_list_iter);
			}

		   __send_discover_response(dbus_info->dbus_obj, dbus_info->invocation, FIDO_ERROR_NONE,
										   asm_resp_json_arr, data_len);
		}
		else
		   __send_discover_response(dbus_info->dbus_obj, dbus_info->invocation, FIDO_ERROR_NOT_SUPPORTED,
										   NULL, 0);
	}

	if (asm_resp_list != NULL)
		g_list_free_full(asm_resp_list, __free_asm_discover_response_list_item);
}

static void
_send_process_response(_process_cb_data_t *cb_data, int tz_err_code, char *uaf_response_json)
{
	_INFO("_send_process_response");

	/*TODO*/
	_dbus_info_t *dbus_info = (_dbus_info_t *)(cb_data->dbus_info);
	if (dbus_info != NULL)
	{
		if (cb_data->type == _PROCESS_TYPE_CHECK_POLICY) {
			_INFO("before fido_complete_fido_uaf_check_policy");
			fido_complete_fido_uaf_check_policy(dbus_info->dbus_obj, dbus_info->invocation, tz_err_code);
			goto CATCH;
		}

		_INFO("before fido_complete_fido_uaf_process_operation");

		if (uaf_response_json != NULL)
			fido_complete_fido_uaf_process_operation(dbus_info->dbus_obj, dbus_info->invocation, FIDO_ERROR_NONE,
											   uaf_response_json);
		else
			fido_complete_fido_uaf_process_operation(dbus_info->dbus_obj, dbus_info->invocation, tz_err_code, _EMPTY_JSON_STRING);
	}

CATCH:
	SAFE_DELETE(uaf_response_json);
	_free_message(cb_data->uaf_req);

	SAFE_DELETE(cb_data->dbus_info);

	if (cb_data->type == _PROCESS_TYPE_AUTH)
		_free_fido_asm_auth_in((_fido_asm_auth_in_t*)(cb_data->asm_in));
	else if (cb_data->type == _PROCESS_TYPE_REG)
		_free_fido_asm_reg_in((_fido_asm_reg_in_t*)(cb_data->asm_in));
	else if (cb_data->type == _PROCESS_TYPE_DEREG)
		_free_fido_asm_dereg_in((_fido_asm_dereg_in_t*)(cb_data->asm_in));
	else
		SAFE_DELETE(cb_data->asm_in);

	SAFE_DELETE(cb_data);
}

void
_discover_response_intermediate_cb(GList *asm_response_list, void *user_data)
{
	_INFO("_discover_response_intermediate_cb");

	_fido_discover_asm_cb_data_t *cb_data = (_fido_discover_asm_cb_data_t *)user_data;

	int error = FIDO_ERROR_NONE;
	GList *asm_auth_list = NULL;

	if (asm_response_list == NULL)
		_ERR("Discover response failed");
	else {
		asm_auth_list = _uaf_parser_parse_asm_response_discover(asm_response_list, &error);
	}

	(cb_data->cb)(error, 0, asm_auth_list, cb_data->user_data);

	if (asm_response_list != NULL)
		g_list_free_full(asm_response_list, __free_asm_discover_response_list_item);
}

static int
__fido_uaf_discover_internal(_fido_discover_asm_cb callback, void *user_data)
{
	_INFO("__fido_uaf_discover_internal");

	_fido_discover_asm_cb_data_t *cb_data_inter_mediate = (_fido_discover_asm_cb_data_t *) calloc(1, sizeof(_fido_discover_asm_cb_data_t));
	cb_data_inter_mediate->cb = callback;
	cb_data_inter_mediate->user_data = user_data;

	return _asm_plugin_mgr_discover_all(_discover_response_intermediate_cb, cb_data_inter_mediate);
}

static void
_asm_response_auth_process(int error_code, const char *asm_response_json, void *user_data)
{
	_INFO("_asm_response_auth_process");

	if (user_data == NULL)
		_ERR("user_data is NULL");

	_process_cb_data_t *cb_data = (_process_cb_data_t*)user_data;
	if (cb_data == NULL) {
		_ERR("_process_cb_data_t not found");
		return;
	}

	_INFO("error_code = [%d]", error_code);

	if (error_code != 0) {
		_ERR("ASM response contains error code [%d]", error_code);
		_send_process_response((_process_cb_data_t *)user_data, error_code, NULL);
		return;
	}

	_asm_out_t *asm_out = NULL;

	_INFO("before _uaf_parser_parse_asm_response_auth");

	int parser_err = 0;
	asm_out = _uaf_parser_parse_asm_response_auth(asm_response_json, &parser_err);
	if (parser_err != 0 || asm_out == NULL) {
		_ERR("_uaf_parser_parse_asm_response_auth failed");

		int uaf_err_code = _convert_asm_status_code_to_uaf_error(parser_err);
		if (uaf_err_code == FIDO_ERROR_NONE)
			_send_process_response(cb_data, FIDO_ERROR_PROTOCOL_ERROR, NULL);
		else
			_send_process_response(cb_data, uaf_err_code, NULL);

		_free_asm_out(asm_out);
		asm_out = NULL;

		return;
	}

	_asm_auth_out_t *asm_auth_out = (_asm_auth_out_t*)(asm_out->response_data);

	_fido_asm_auth_in_t *asm_auth_in = (_fido_asm_auth_in_t *) cb_data->asm_in;

	_message_t *uaf_message = cb_data->uaf_req;

	_op_header_t *header = uaf_message->header;

	char *uaf_response_json = NULL;


	/* TODO : Add logic to accumulate multiple auth response and form the assertion_list*/
	GList *assertion_list = NULL;

	_auth_reg_assertion_t *asst_data = (_auth_reg_assertion_t*)calloc(1, sizeof(_auth_reg_assertion_t));

	_INFO("before assertion");
	asst_data->assertion = strdup(asm_auth_out->assertion);

	_INFO("before assertion_schm");
	asst_data->assertion_schm = strdup(asm_auth_out->assertion_scheme);

	assertion_list = g_list_append(assertion_list, asst_data);

	assertion_list = g_list_first(assertion_list);


	_INFO("before _uaf_composer_compose_uaf_process_response_auth");
	parser_err = _uaf_composer_compose_uaf_process_response_auth(header, asm_auth_in->final_challenge,
												   assertion_list, &uaf_response_json);

	g_list_free_full(assertion_list, _free_auth_reg_assertion_list_item);

	_free_asm_out(asm_out);
	asm_out = NULL;

	if (parser_err != 0) {
		_ERR("_uaf_composer_compose_uaf_process_response_auth failed");
		_send_process_response((_process_cb_data_t *)user_data, FIDO_ERROR_INVALID_PARAMETER, NULL);
		return;
	}

	_send_process_response(cb_data, FIDO_ERROR_NONE, uaf_response_json);
}

static void
_asm_response_reg_process(int error_code, const char *asm_response_json, void *user_data)
{
	_INFO("_asm_response_reg_process");

	_process_cb_data_t *cb_data = (_process_cb_data_t*)user_data;
	if (cb_data == NULL)
		return;

	if (error_code != 0) {
		_ERR("ASM response contains error code [%d]", error_code);

		_send_process_response((_process_cb_data_t *)user_data, error_code, NULL);

		return;
	}

	_asm_out_t *asm_out = NULL;
	int parser_err = 0;
	asm_out = _uaf_parser_parse_asm_response_reg(asm_response_json, &parser_err);
	if (parser_err != 0 || asm_out == NULL) {
		_ERR("_uaf_parser_parse_asm_response_reg failed");

		int uaf_err_code = _convert_asm_status_code_to_uaf_error(parser_err);
		if (uaf_err_code == FIDO_ERROR_NONE)
			_send_process_response((_process_cb_data_t *)user_data, FIDO_ERROR_PROTOCOL_ERROR, NULL);
		else
			_send_process_response((_process_cb_data_t *)user_data, uaf_err_code, NULL);

		_free_asm_out(asm_out);

		return;
	}

	_asm_reg_out_t *asm_reg_out = (_asm_reg_out_t*)(asm_out->response_data);

	_fido_asm_reg_in_t *asm_reg_in = (_fido_asm_reg_in_t *)(cb_data->asm_in);

	_message_t *uaf_req = cb_data->uaf_req;
	_reg_request_t *uaf_reg_req = (_reg_request_t*)(uaf_req->data);
	_op_header_t *header = uaf_req->header;

	char *uaf_response_json = NULL;

	/* TODO : Add logic to accumulate multiple auth response and form the assertion_list*/
	_auth_reg_assertion_t *ass_data = (_auth_reg_assertion_t*) calloc(1, sizeof(_auth_reg_assertion_t));
	ass_data->assertion = __dup_string(asm_reg_out->assertion);
	ass_data->assertion_schm = __dup_string(asm_reg_out->assertion_schm);
	ass_data->tc_disp_char_list = uaf_reg_req->png_list;


	_free_asm_out(asm_out);
	asm_out = NULL;

	GList *ass_list = NULL;
	ass_list = g_list_append(ass_list, ass_data);

	parser_err = _uaf_composer_compose_uaf_process_response_reg(header, asm_reg_in->final_challenge,
												   ass_list, &uaf_response_json);

	g_list_free_full(ass_list, _free_auth_reg_assertion_list_item);

	if (parser_err != 0) {
		_ERR("_uaf_composer_compose_uaf_process_response_reg failed");
		_send_process_response((_process_cb_data_t *)user_data, FIDO_ERROR_INVALID_PARAMETER, NULL);
		return;
	}

	_send_process_response((_process_cb_data_t *)user_data, FIDO_ERROR_NONE, uaf_response_json);
}

static void
__handle_reg(_process_cb_data_t *cb_data, _matched_auth_data_t *matched_auth)
{
	_INFO("");

	_message_t *uaf_req = (_message_t *)(cb_data->uaf_req);

	_reg_request_t *uaf_reg_req = (_reg_request_t *)(cb_data->uaf_req->data);

	uaf_reg_req->png_list = matched_auth->tc_display_png_characteristics;

	_fido_asm_reg_in_t *reg_in = (_fido_asm_reg_in_t*) calloc(1, sizeof(_fido_asm_reg_in_t));

	/*If no app-id mentioned in UAF request*/
	if (cb_data->uaf_req->header->app_id == NULL) {
		if (cb_data->uaf_req->facet_id == NULL) {
			_ERR("Failed to get app id");
			_send_process_response(cb_data, FIDO_ERROR_UNTRUSTED_FACET_ID, NULL);
			_free_fido_asm_reg_in(reg_in);
			return;
		}
		/* app id*/
		cb_data->uaf_req->header->app_id = strdup(cb_data->uaf_req->facet_id);
		reg_in->app_id = strdup(cb_data->uaf_req->header->app_id);
	}
	else {
		/* app id*/
		reg_in->app_id = strdup(cb_data->uaf_req->header->app_id);
	}

	/* user name */
	if (uaf_reg_req->user_name != NULL)
		reg_in->user_name = strdup(uaf_reg_req->user_name);

	_INFO("");

	char *fc_json = _uaf_composer_compose_final_challenge(reg_in->app_id, uaf_reg_req->challenge,
														  uaf_req->facet_id, cb_data->uaf_req->channel_binding);

	if (fc_json == NULL) {
		_ERR("Failed to compose final challenge");
		_send_process_response(cb_data, FIDO_ERROR_PROTOCOL_ERROR, NULL);
		_free_fido_asm_reg_in(reg_in);
		return;
	}

	_INFO("");
	/* Final challenge */
	reg_in->final_challenge = fc_json;

	int auth_idx_int = -1;
	sscanf(matched_auth->auth_index, "%d", &auth_idx_int);

	reg_in->attestation_type = matched_auth->att_type;

	_version_t *version = (_version_t *)calloc(1, sizeof(_version_t));
	version->major = _VERSION_MAJOR;
	version->minor = _VERSION_MINOR;

	char *asm_req_json = NULL;

	cb_data->asm_in = reg_in;

	_INFO("");
	int ret = _uaf_composer_compose_asm_reg_request(version, auth_idx_int, reg_in, &asm_req_json);
	if (ret == 0 && asm_req_json != NULL)
		_asm_ipc_send(matched_auth->asm_id,
					  asm_req_json, _asm_response_reg_process, cb_data);
	else
		_send_process_response(cb_data, FIDO_ERROR_PROTOCOL_ERROR, NULL);

	SAFE_DELETE(asm_req_json);
	SAFE_DELETE(version);

}

static GList *
__copy_convert_uaf_trans_list(GList *uaf_tr_list)
{
	RET_IF_FAIL(uaf_tr_list != NULL, NULL);

	GList *asm_tr_list = NULL;

	GList *uaf_tr_list_iter = g_list_first(uaf_tr_list);
	while (uaf_tr_list_iter != NULL) {

		_auth_transaction_t *uaf_tr = (_auth_transaction_t*)(uaf_tr_list_iter->data);

		_fido_asm_transaction_t *asm_tr = calloc(1, sizeof(_fido_asm_transaction_t));

		asm_tr->content = __dup_string(uaf_tr->content);
		asm_tr->content_type = __dup_string(uaf_tr->content_type);
		if (uaf_tr->display_charac != NULL) {
			asm_tr->display_charac = calloc(1, sizeof(_fido_asm_display_png_characteristics_descriptor_t));

			asm_tr->display_charac->bit_depth = uaf_tr->display_charac->bit_depth;
			asm_tr->display_charac->color_type = uaf_tr->display_charac->color_type;
			asm_tr->display_charac->compression = uaf_tr->display_charac->compression;
			asm_tr->display_charac->filter = uaf_tr->display_charac->filter;
			asm_tr->display_charac->height = uaf_tr->display_charac->height;
			asm_tr->display_charac->interlace = uaf_tr->display_charac->interlace;
			asm_tr->display_charac->width = uaf_tr->display_charac->width;

			if (uaf_tr->display_charac->plte != NULL) {

				GList *uaf_plte_iter = g_list_first(uaf_tr->display_charac->plte);
				while (uaf_plte_iter != NULL) {
					fido_rgb_pallette_entry_s *uaf_plte_entry = (fido_rgb_pallette_entry_s*)(uaf_plte_iter->data);

					fido_rgb_pallette_entry_s *asm_plte_entry = calloc(1, sizeof(fido_rgb_pallette_entry_s));
					asm_plte_entry->r = uaf_plte_entry->r;
					asm_plte_entry->g = uaf_plte_entry->g;
					asm_plte_entry->b = uaf_plte_entry->b;

					asm_tr->display_charac->plte = g_list_append(asm_tr->display_charac->plte, asm_plte_entry);

					uaf_plte_iter = uaf_plte_iter->next;
				}
			}
		}

		asm_tr_list = g_list_append(asm_tr_list, asm_tr);

		uaf_tr_list_iter = uaf_tr_list_iter->next;
	}

	if (asm_tr_list != NULL) {
		asm_tr_list = g_list_first(asm_tr_list);
		_INFO("Trans list = [%d]", g_list_length(asm_tr_list));
	}
	return asm_tr_list;
}

static GList*
__copy_string_list(GList *src)
{
	_INFO("");

	RET_IF_FAIL(src != NULL, NULL);

	GList *dest = NULL;

	GList *iter = g_list_first(src);
	while (iter != NULL) {
		char *str = (char*)(iter->data);
		dest = g_list_append(dest, strdup(str));

		iter = iter->next;
		_INFO("");
	}

	_INFO("");
	return dest;
}

static void
__handle_auth(_process_cb_data_t *cb_data, _matched_auth_data_t *matched_auth)
{
	_INFO("__handle_auth");

	_auth_request_t *uaf_auth_req = (_auth_request_t*)(cb_data->uaf_req->data);

	_fido_asm_auth_in_t *auth_asm_in = (_fido_asm_auth_in_t*)calloc(1, sizeof(_fido_asm_auth_in_t));

	if (cb_data->uaf_req->header->app_id == NULL) {

		if (cb_data->uaf_req->facet_id == NULL) {
			_ERR("Failed to get app id");
			_send_process_response(cb_data, FIDO_ERROR_PERMISSION_DENIED, NULL);
			_free_fido_asm_auth_in(auth_asm_in);
			return;
		}
		cb_data->uaf_req->header->app_id = strdup(cb_data->uaf_req->facet_id);
		auth_asm_in->app_id = strdup(cb_data->uaf_req->facet_id);
	}
	else {
		auth_asm_in->app_id = strdup(cb_data->uaf_req->header->app_id);
	}

	char *fc_json = _uaf_composer_compose_final_challenge(cb_data->uaf_req->header->app_id,
														  uaf_auth_req->challenge, cb_data->uaf_req->facet_id,
														  cb_data->uaf_req->channel_binding);
	if (fc_json == NULL) {
		_ERR("Failed to compose final challenge");
		_send_process_response(cb_data, FIDO_ERROR_PROTOCOL_ERROR, NULL);

		_free_fido_asm_auth_in(auth_asm_in);
		return;
	}

	/*keyIDs*/
	auth_asm_in->key_ids = __copy_string_list(matched_auth->key_ids);

	/* Final challenge */
	auth_asm_in->final_challenge = fc_json;

	/*Transaction*/
	auth_asm_in->trans_list = __copy_convert_uaf_trans_list(uaf_auth_req->transaction_list);


	cb_data->asm_in = auth_asm_in;

	char *asm_req_json = NULL;
	_version_t *version = (_version_t *)calloc(1, sizeof(_version_t));
	version->major = _VERSION_MAJOR;
	version->minor = _VERSION_MINOR;

	int auth_idx_int = -1;
	sscanf(matched_auth->auth_index, "%d", &auth_idx_int);
	if (auth_idx_int == -1) {
		_ERR("ASM in data missing");
		_send_process_response(cb_data, FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR, NULL);

		_free_fido_asm_auth_in(auth_asm_in);
		SAFE_DELETE(version);

		return;
	}

	int ret = _uaf_composer_compose_asm_auth_request(version, auth_idx_int, auth_asm_in, &asm_req_json);
	if (ret == 0 && asm_req_json != NULL) {
		_asm_ipc_send(matched_auth->asm_id,
					  asm_req_json, _asm_response_auth_process, cb_data);
	}
	else {
		_send_process_response(cb_data, FIDO_ERROR_INVALID_PARAMETER, NULL);
	}

	SAFE_DELETE(version);
	SAFE_DELETE(asm_req_json);
}

static void
_ui_response_callback(int error_code, _ui_auth_data_t *selected_auth_data, void *user_data)
{
	if (selected_auth_data == NULL) {
			_ERR("User did not select any Authenticator");
			_send_process_response((_process_cb_data_t *)user_data, error_code, NULL);
			free(selected_auth_data);
			return;
	}

	_INFO("User selected [%s] authenticator index", selected_auth_data->auth_index);

	_process_cb_data_t *cb_data = (_process_cb_data_t*)user_data;


	_matched_auth_data_t *match_data = (_matched_auth_data_t*)calloc(1, sizeof(_matched_auth_data_t));
	match_data->att_type = selected_auth_data->att_type;
	match_data->auth_index = selected_auth_data->auth_index;
	match_data->asm_id = strdup(selected_auth_data->asm_id);

	if (cb_data->type == _PROCESS_TYPE_REG)
		__handle_reg(cb_data, match_data);

	if (cb_data->type == _PROCESS_TYPE_AUTH)
		__handle_auth(cb_data, match_data);

	_free_matched_auth_data(match_data);

}

static void
_asm_response_dereg_process(int error_code, const char *asm_response_json, void *user_data)
{
	_dereg_q_t *dereg_q = (_dereg_q_t*)(user_data);
	_process_cb_data_t *cb_data = (_process_cb_data_t*)(dereg_q->cb_data);

	if (cb_data == NULL)
		return;

	/*Process next dereg*/
	GQueue *q = (GQueue*) (dereg_q->dereg_asm_in_q);
	if (g_queue_is_empty(q) == FALSE)
		__process_dereg_queue(user_data);
	else {
		/*ASM does not return success/faliure for dereg*/
		_INFO("Ignoring ASM's response for dereg");
		_send_process_response((_process_cb_data_t *)cb_data, FIDO_ERROR_NONE, NULL);

		_INFO("Deleting dereg_asm_in_q");
		/*Elements were deleted during pop*/
		g_queue_free(dereg_q->dereg_asm_in_q);
		dereg_q->dereg_asm_in_q = NULL;
		_INFO("After Deleting dereg_asm_in_q");
	}

}

static void
__process_dereg_queue(_dereg_q_t *dereg_q)
{
	_INFO("__process_dereg_queue");

	GQueue *q = dereg_q->dereg_asm_in_q;
	if (q == NULL)
		return;

	if (g_queue_is_empty(q) == true) {
		_INFO("Deleting dereg_asm_in_q");
		g_queue_free(dereg_q->dereg_asm_in_q);
		dereg_q->dereg_asm_in_q = NULL;
		_INFO("After Deleting dereg_asm_in_q");
		return;
	}

	_process_cb_data_t *cb_data = (_process_cb_data_t*)(dereg_q->cb_data);
	_message_t *uaf_message = cb_data->uaf_req;

	_matched_auth_dereg_t *dereg_data = (_matched_auth_dereg_t*)(g_queue_pop_head(q));

	char *asm_req_json = NULL;

	int auth_index_int = _INVALID_INT;
	sscanf(dereg_data->auth_index, "%d", &auth_index_int);

	_INFO("Auth index for dereg req = [%d]", auth_index_int);

	int ret = _uaf_composer_compose_asm_dereg_request(uaf_message->header->version, auth_index_int,
													  dereg_data, &asm_req_json);

	/*TODO : ASM does not return anything for dereg, so do not wait for response, send back
	* success always.
	*/
	if (ret == 0 && asm_req_json != NULL) {
		_asm_ipc_send(dereg_data->asm_id,
					  asm_req_json, _asm_response_dereg_process, dereg_q);
	}
	else {
		_send_process_response(cb_data, FIDO_ERROR_INVALID_PARAMETER, NULL);
	}

	_free_matched_auth_dereg(dereg_data);
	SAFE_DELETE(asm_req_json);

}

static GList*
__get_keyid_list_from_app_reg(GList *app_reg_list)
{
	_INFO("__get_keyid_list_from_app_reg");

	RET_IF_FAIL(app_reg_list != NULL, NULL);

	GList *key_id_list = NULL;

	GList *app_reg_list_iter = g_list_first(app_reg_list);
	while (app_reg_list_iter != NULL) {

		_asm_app_reg_t *app_reg = (_asm_app_reg_t*)(app_reg_list_iter->data);
		if (app_reg != NULL) {

			if (app_reg->key_id_list != NULL) {
				GList *key_id_list_iter = g_list_first(app_reg->key_id_list);
				while (key_id_list_iter != NULL) {
					char *key_id = (char*)(key_id_list_iter->data);
					if (key_id != NULL) {
						key_id_list = g_list_append(key_id_list, strdup(key_id));
						_INFO("[%s]", key_id);
					}

					key_id_list_iter = key_id_list_iter->next;
				}
			}
		}

		app_reg_list_iter = app_reg_list_iter->next;
	}

	return key_id_list;
}

static GList *
__get_auth_list_with_keyids(GList *available_authenticators)
{
	_INFO("__get_auth_list_with_keyids");

	GList *available_authenticators_full = NULL;

	GList *avl_auth_iter = g_list_first(available_authenticators);
	while (avl_auth_iter != NULL) {

		fido_authenticator_s *asm_auth = (fido_authenticator_s*)(avl_auth_iter->data);
		if (asm_auth != NULL) {
			char *get_reg_json = _uaf_composer_compose_get_registrations_request(asm_auth->auth_index);
			char *get_reg_resp = _asm_ipc_send_sync(asm_auth->asm_id, get_reg_json);

			if (get_reg_resp != NULL)
				_INFO("_asm_ipc_send_sync = [%s]", get_reg_resp);

			_asm_get_reg_out_t *get_reg_out = _uaf_parser_parser_asm_get_reg_response(get_reg_resp);
			if (get_reg_out != NULL) {
				asm_auth->key_ids = __get_keyid_list_from_app_reg(get_reg_out->app_reg_list);
				asm_auth->key_ids = g_list_first(asm_auth->key_ids);
				_INFO(" asm_auth->key_ids count = [%d]",  g_list_length(asm_auth->key_ids));
			}
			available_authenticators_full = g_list_append(available_authenticators_full, asm_auth);

			SAFE_DELETE(get_reg_json);
			SAFE_DELETE(get_reg_resp);
			_free_asm_get_reg_out(get_reg_out);

		}
		avl_auth_iter = avl_auth_iter->next;
	}

	return available_authenticators_full;
}

static void
__free_matched_dereg_auth_data_list_item(gpointer data)
{
	RET_IF_FAIL_VOID(data != NULL);

	_free_matched_auth_dereg((_matched_auth_dereg_t*)data);
}

static void
_discover_response_cb_for_process(int tz_error_code, int error_code, GList *available_authenticators, void *user_data)
{
	_INFO("_discover_response_cb_for_process [%p]", user_data);

	_process_cb_data_t *cb_data = (_process_cb_data_t*)user_data;

	if (tz_error_code != FIDO_ERROR_NONE) {
		_ERR("Failed to get available authenticator info [%d]", tz_error_code);
		_send_process_response(cb_data, FIDO_ERROR_NOT_SUPPORTED, NULL);
		return;
	}

	if (available_authenticators == NULL) {
		_ERR("No supported authenticators found");
		_send_process_response(cb_data, FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR, NULL);
		return;
	}

	_INFO("cb_data->type = [%d]", cb_data->type);

	GList *available_authenticators_full = g_list_first(available_authenticators);

	if (cb_data->type == _PROCESS_TYPE_CHECK_POLICY) {

		_INFO("_PROCESS_TYPE_CHECK_POLICY");

		if (cb_data->uaf_req->header->operation != NULL)
			_INFO("operation = [%s]", cb_data->uaf_req->header->operation);
		else
			_ERR("operation = [NULL]");

		if ((strcmp(cb_data->uaf_req->header->operation, _UAF_OPERATION_NAME_KEY_REG) == 0)
					 || ((strcmp(cb_data->uaf_req->header->operation, _UAF_OPERATION_NAME_KEY_AUTH) == 0))) {

			_policy_t *policy = NULL;

			if (strcmp(cb_data->uaf_req->header->operation, _UAF_OPERATION_NAME_KEY_REG) == 0) {
				_reg_request_t *uaf_reg_req = (_reg_request_t *)(cb_data->uaf_req->data);
				policy = uaf_reg_req->policy;
				 _INFO("_PROCESS_TYPE_CHECK_POLICY for reg");
			}
			else if (strcmp(cb_data->uaf_req->header->operation, _UAF_OPERATION_NAME_KEY_AUTH) == 0) {
				_auth_request_t *uaf_auth_req = (_auth_request_t *)(cb_data->uaf_req->data);
				policy = uaf_auth_req->policy;
				_INFO("_PROCESS_TYPE_CHECK_POLICY for auth");
			}

			if (policy->is_keyid_present == true) {
				/*Available authenticators' keyIDs can be fetched via GetRegistrations ASM op*/
				_INFO("Need to call GetRegistrations to match policy");
				GList *avl_auth_list_full_temp = __get_auth_list_with_keyids(available_authenticators);
				if (avl_auth_list_full_temp != NULL) {
					g_list_free(available_authenticators_full);

					available_authenticators_full = g_list_first(avl_auth_list_full_temp);
				}

			}
			GList *allowed_auth_list = _policy_checker_get_matched_auth_list(policy, available_authenticators_full);
			g_list_free_full(available_authenticators_full, _free_asm_auth_list);

			if ((allowed_auth_list != NULL) && g_list_length(allowed_auth_list) > 0) {

				_send_process_response(cb_data, FIDO_ERROR_NONE, NULL);
			}
			else {
				_send_process_response(cb_data, FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR, NULL);
			}

			if (allowed_auth_list != NULL)
				g_list_free_full(allowed_auth_list, _free_matched_auth_data);

		}
		else if (strcmp(cb_data->uaf_req->header->operation, _UAF_OPERATION_NAME_KEY_DE_REG) == 0) {

			_dereg_request_t *dereg_req = (_dereg_request_t*)(cb_data->uaf_req->data);

			/* _matched_auth_dereg_t list*/
			if (cb_data->uaf_req->header->app_id == NULL)
				cb_data->uaf_req->header->app_id = strdup(cb_data->uaf_req->facet_id);

			GList *matched_auth_list = _policy_checker_get_matched_auth_list_dereg(cb_data->uaf_req->header->app_id, dereg_req->auth_info_list,
																				   available_authenticators_full);
			g_list_free_full(available_authenticators_full, _free_asm_auth_list);

			if ((matched_auth_list != NULL) && g_list_length(matched_auth_list) > 0) {

				_send_process_response(cb_data, FIDO_ERROR_NONE, NULL);
			}
			else {
				_send_process_response(cb_data, FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR, NULL);
			}

			if (matched_auth_list != NULL)
				g_list_free_full(matched_auth_list, __free_matched_dereg_auth_data_list_item);

		}

		return;
	}
	if (cb_data->type == _PROCESS_TYPE_DEREG) {


		_dereg_request_t *dereg_req = (_dereg_request_t*)(cb_data->uaf_req->data);

		if (cb_data->uaf_req->header->app_id == NULL)
			cb_data->uaf_req->header->app_id = strdup(cb_data->uaf_req->facet_id);

		/* _matched_auth_dereg_t list*/
		GList *matched_auth_list = _policy_checker_get_matched_auth_list_dereg(cb_data->uaf_req->header->app_id, dereg_req->auth_info_list,
																			   available_authenticators_full);

		g_list_free_full(available_authenticators_full, _free_asm_auth_list);

		if (matched_auth_list == NULL){
			_ERR("No supported authenticators found");
			_send_process_response(cb_data, FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR, NULL);
			return;
		}

		_dereg_q_t *dereg_q = (_dereg_q_t*) calloc(1, sizeof(_dereg_q_t));

		GList *matched_auth_list_iter = g_list_first(matched_auth_list);
		while (matched_auth_list_iter != NULL) {
			_matched_auth_dereg_t *dereg_auth_matched = (_matched_auth_dereg_t*) (matched_auth_list_iter->data);

			if (dereg_auth_matched != NULL) {
				GQueue *q = dereg_q->dereg_asm_in_q;

				if (q == NULL)
					dereg_q->dereg_asm_in_q = g_queue_new();

				g_queue_push_head(dereg_q->dereg_asm_in_q, dereg_auth_matched);
			}
			matched_auth_list_iter = matched_auth_list_iter->next;
		}

		/*The elements will be deleted while freeing dereg_q->dereg_asm_in_q*/
		g_list_free(matched_auth_list);

		dereg_q->cb_data = cb_data;

		__process_dereg_queue(dereg_q);

		return;
	}

	_policy_t *policy = NULL;

	if (cb_data->type == _PROCESS_TYPE_REG) {
		_reg_request_t *uaf_reg_req = (_reg_request_t *)(cb_data->uaf_req->data);
		policy = uaf_reg_req->policy;
	}
	else if (cb_data->type == _PROCESS_TYPE_AUTH) {
		_auth_request_t *uaf_auth_req = (_auth_request_t *)(cb_data->uaf_req->data);
		policy = uaf_auth_req->policy;
	}
	else {
		_send_process_response(cb_data, FIDO_ERROR_UNKNOWN, NULL);
		return;
	}

	if (policy->is_keyid_present == true) {
		/*Available authenticators' keyIDs can be fetched via GetRegistrations ASM op*/
		_INFO("Need to call GetRegistrations to match policy");
		GList *avl_auth_list_full_temp = __get_auth_list_with_keyids(available_authenticators);
		if (avl_auth_list_full_temp != NULL) {
			g_list_free(available_authenticators_full);
			available_authenticators_full = g_list_first(avl_auth_list_full_temp);
		}

	}

	GList *allowed_auth_list = _policy_checker_get_matched_auth_list(policy, available_authenticators_full);
	g_list_free_full(available_authenticators_full, _free_asm_auth_list);

	if (allowed_auth_list == NULL){
		_ERR("No supported authenticators found");
		_send_process_response(cb_data, FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR, NULL);

		return;
	}

	_INFO("");
	allowed_auth_list = g_list_first(allowed_auth_list);

	if (g_list_length(allowed_auth_list) > 1) {
		_INFO("");

		GList *ui_data_list = NULL;

		GList *allowed_auth_list_iter = allowed_auth_list;
		while (allowed_auth_list_iter != NULL) {
			_matched_auth_data_t *match_data = (_matched_auth_data_t *)(allowed_auth_list_iter->data);

			if (match_data != NULL) {

				_ui_auth_data_t *ui_data = (_ui_auth_data_t*) calloc(1, sizeof(_ui_auth_data_t));
				if (match_data->asm_id != NULL)
					ui_data->asm_id = strdup(match_data->asm_id);
				else
					_ERR("No ASM id found to send to UI!!");

				ui_data->auth_index = strdup(match_data->auth_index);
				ui_data->att_type = match_data->att_type;

				ui_data->label = strdup(match_data->label);

				ui_data_list = g_list_append(ui_data_list, ui_data);

				allowed_auth_list_iter = allowed_auth_list_iter->next;
			}
		}

		int ret = _auth_ui_selector_send(ui_data_list, _ui_response_callback, cb_data);
		if (ret != 0) {
			_ERR("Failed to invoke selector UI");
			_send_process_response(cb_data, FIDO_ERROR_NOT_SUPPORTED, NULL);
			if (allowed_auth_list != NULL)
				g_list_free_full(allowed_auth_list, _free_matched_auth_data);
			return;
		}
	}
	else {
		_INFO("");
		GList *allowed_auth_list_iter = allowed_auth_list;
		_matched_auth_data_t *match_data = (_matched_auth_data_t *)(allowed_auth_list_iter->data);

		if (cb_data->type == _PROCESS_TYPE_REG)
			__handle_reg(cb_data, match_data);

		else if (cb_data->type == _PROCESS_TYPE_AUTH)
			__handle_auth(cb_data, match_data);

	}
	if (allowed_auth_list != NULL)
		g_list_free_full(allowed_auth_list, _free_matched_auth_data);

}

static int
_handle_process_message(_process_cb_data_t *cb_data)
{
	return __fido_uaf_discover_internal(_discover_response_cb_for_process, cb_data);
}

static void
__facet_id_cb(int err, const char *facet_id, void *user_data)
{
	_INFO("__facet_id_cb");
	if (facet_id != NULL)
		_INFO("[%s]", facet_id);

	_process_cb_data_t *cb_data = (_process_cb_data_t*)user_data;

	if (err != FIDO_ERROR_NONE || facet_id == NULL) {
		_send_process_response(cb_data, err, NULL);
		return;
	}

	cb_data->uaf_req->facet_id = strdup(facet_id);

	int error_code = FIDO_ERROR_NONE;

	if (cb_data->type != _PROCESS_TYPE_CHECK_POLICY) {

		/**
		 * 1. Extract embedded policy to find the suitable authenticator(s)
		 * 2. Show UI to let user select one, if (1) gives multiple result.
		 * 3. Compose ASMRequest in json format
		 * 4. Send the same to asm
		 * 5. Send the ASMResponse to application.
		 */

		if (strcmp(cb_data->uaf_req->header->operation, _UAF_OPERATION_NAME_KEY_REG) == 0)
			cb_data->type = _PROCESS_TYPE_REG;

		else if (strcmp(cb_data->uaf_req->header->operation, _UAF_OPERATION_NAME_KEY_AUTH) == 0)
			cb_data->type = _PROCESS_TYPE_AUTH;

		else if (strcmp(cb_data->uaf_req->header->operation, _UAF_OPERATION_NAME_KEY_DE_REG) == 0)
			cb_data->type = _PROCESS_TYPE_DEREG;

		else {
			 _send_process_response(cb_data, FIDO_ERROR_INVALID_PARAMETER, NULL);
			 return;
		}
	}

	error_code = _handle_process_message(cb_data);

	if (error_code != FIDO_ERROR_NONE) {
		_send_process_response(cb_data, error_code, NULL);
	}
}

gboolean
_dbus_on_fido_init(Fido *object, GDBusMethodInvocation *invocation)
{
	fido_complete_fido_uaf_init(object, invocation, FIDO_ERROR_NONE);

	return true;
}

gboolean
_dbus_on_fido_deinit(Fido *object, GDBusMethodInvocation *invocation)
{
	if (is_allowed_to_call(invocation, _FIDO_CLIENT_PRIVILEGE) == false) {
		fido_complete_fido_uaf_deinit(object, invocation, FIDO_ERROR_PERMISSION_DENIED);
	}
	else {
		//_auth_ui_selector_deinit();
		fido_complete_fido_uaf_deinit(object, invocation, FIDO_ERROR_NONE);
	}

	return true;
}

gboolean
_dbus_on_fido_discover(Fido *object, GDBusMethodInvocation *invocation)
{
	_INFO("_dbus_on_fido_discover");
	if (is_allowed_to_call(invocation, _FIDO_CLIENT_PRIVILEGE) == false) {

		__send_discover_response(object, invocation, FIDO_ERROR_PERMISSION_DENIED,
										NULL, 0);
		return true;
	}

	_dbus_info_t *dbus_info = (_dbus_info_t *)calloc(1, sizeof(_dbus_info_t));
	dbus_info->dbus_obj = object;
	dbus_info->invocation = invocation;

	int ret = _asm_plugin_mgr_discover_all(_asm_get_info_cb, dbus_info);
	if (ret != FIDO_ERROR_NONE) {

		_ERR("_asm_ipc_send failed = [%d]", ret);
		__send_discover_response(dbus_info->dbus_obj, dbus_info->invocation, FIDO_ERROR_NOT_SUPPORTED,
										NULL, 0);

		SAFE_DELETE(dbus_info);

	}

	return true;
}

gboolean
_dbus_handle_process_or_check_policy(Fido *object, GDBusMethodInvocation *invocation, 
									const gchar *uaf_request_json, const gchar *channel_binding,
									 _process_type_t type)
{

	_INFO("_dbus_handle_process_or_check_policy");

	_process_cb_data_t *cb_data = (_process_cb_data_t*) calloc(1, sizeof(_process_cb_data_t));
	_dbus_info_t *dbus_info = (_dbus_info_t *)calloc(1, sizeof(_dbus_info_t));
	dbus_info->dbus_obj = object;
	dbus_info->invocation = invocation;
	cb_data->dbus_info = dbus_info;
	cb_data->type = type;

	if (is_allowed_to_call(invocation, _FIDO_CLIENT_PRIVILEGE) == false) {
		_send_process_response(cb_data, FIDO_ERROR_PERMISSION_DENIED, NULL);
		return true;
	}

	if (uaf_request_json == NULL) {
		_send_process_response(cb_data, FIDO_ERROR_PROTOCOL_ERROR, NULL);
		return true;
	}

	_INFO("%s", uaf_request_json);

	_message_t *uaf_message = _uaf_parser_parse_message(uaf_request_json, channel_binding);
	if (uaf_message == NULL) {
		_send_process_response(cb_data, FIDO_ERROR_PROTOCOL_ERROR, NULL);
		return true;
	}


	cb_data->uaf_req = uaf_message;


	int ret = _verify_and_get_facet_id(uaf_message->header->app_id, invocation, __facet_id_cb, cb_data);
	if (ret != FIDO_ERROR_NONE) {
		_send_process_response(cb_data, FIDO_ERROR_UNTRUSTED_FACET_ID, NULL);
		return true;
	}

	return true;
}

gboolean
_dbus_on_fido_uaf_is_supported(Fido *object, GDBusMethodInvocation *invocation,
							   const gchar *uaf_request_json)
{
	_INFO("_dbus_on_fido_uaf_is_supported");

	return _dbus_handle_process_or_check_policy(object, invocation, uaf_request_json, NULL,
												_PROCESS_TYPE_CHECK_POLICY);
}

gboolean
_dbus_on_fido_process_operation(Fido *object, GDBusMethodInvocation *invocation,
									const gchar *uaf_request_json, const gchar* channel_binding_json)
{
	_INFO("_dbus_on_fido_process_operation");

	return _dbus_handle_process_or_check_policy(object, invocation, uaf_request_json,
												channel_binding_json, _PROCESS_TYPE_MIN);
}

/*gboolean
_dbus_on_fido_uaf_notify_result(Fido *object, GDBusMethodInvocation *invocation, const gchar *arg_cookie, gint arg_respose_code,
								const gchar *uaf_response_json)
{
	fido_complete_fido_uaf_notify_result(object, invocation, 0, 0);
	return true;
}*/

static void
on_bus_acquired (GDBusConnection *connection, const gchar *name, gpointer user_data)
{
		dlog_print(DLOG_INFO, "FIDO", "on_bus_acquired");

		_INFO("on_bus_acquired [%s]", name);

		GDBusInterfaceSkeleton* interface = NULL;
		fido_dbus_obj = fido_skeleton_new();
		if (fido_dbus_obj == NULL) {
			_ERR("fido_dbus_obj NULL!!");
			return;
		}

		dlog_print(DLOG_INFO, "FIDO", "G_DBUS_INTERFACE_SKELETON");

		interface = G_DBUS_INTERFACE_SKELETON(fido_dbus_obj);
		if (!g_dbus_interface_skeleton_export(interface, connection, _FIDO_SERVICE_DBUS_PATH, NULL)) {
			_ERR("export failed!!");
			return;
		}

		dlog_print(DLOG_INFO, "FIDO", "g_signal_connect");

		_INFO("connecting fido signals start");

		g_signal_connect(fido_dbus_obj, "handle_fido_uaf_init",
						G_CALLBACK(_dbus_on_fido_init), NULL);

		g_signal_connect(fido_dbus_obj, "handle_fido_uaf_deinit",
						G_CALLBACK(_dbus_on_fido_deinit), NULL);

		g_signal_connect(fido_dbus_obj, "handle_fido_uaf_discover",
						G_CALLBACK(_dbus_on_fido_discover), NULL);

		g_signal_connect(fido_dbus_obj, "handle_fido_uaf_check_policy",
                        G_CALLBACK(_dbus_on_fido_uaf_is_supported), NULL);

		g_signal_connect(fido_dbus_obj, "handle_fido_uaf_process_operation",
						G_CALLBACK(_dbus_on_fido_process_operation), NULL);

//        g_signal_connect(fido_dbus_obj, "handle_fido_uaf_notify_result",
//                        G_CALLBACK(_dbus_on_fido_uaf_notify_result), NULL);

		g_signal_connect(fido_dbus_obj, "handle_ui_response",
						G_CALLBACK(_auth_ui_selector_on_ui_response), NULL);

		if (_asm_plugin_mgr_init() != FIDO_ERROR_NONE) {
			_ERR("Falied to init ASM plugin manager");
			dlog_print(DLOG_INFO, "FIDO", "_asm_plugin_mgr_init failed");
			exit(1);
		}


}

static void
on_name_acquired (GDBusConnection *connection,
						const gchar     *name,
						gpointer         user_data)
{
		_INFO("on_name_acquired");

}

static void
on_name_lost (GDBusConnection *connection,
						const gchar     *name,
						gpointer         user_data)
{
		_INFO("on_name_lost");
		_asm_plugin_mgr_destroy();
		exit (1);
}

static bool
__initialize_dbus(void)
{
	_INFO("__initialize_dbus Enter");

	owner_id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
							 _FIDO_DBUS_NAME,
							 G_BUS_NAME_OWNER_FLAGS_NONE,
							 on_bus_acquired,
							 on_name_acquired,
							 on_name_lost,
							 NULL,
							 NULL);

	_INFO("owner_id=[%d]", owner_id);

	if(owner_id == 0) {
			_INFO("gdbus own failed!!");
			return false;
	}

	_INFO("g_bus_own_name SUCCESS");
	return true;
}

static void
__initialize(void)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init();
#endif

	if (__initialize_dbus() == false) {
		_ERR("DBUS Initialization Failed");
		exit(1);
	}
}

int
main(void)
{
	GMainLoop *mainloop = NULL;

	dlog_print(DLOG_INFO, "FIDO", "start");

	_INFO("Starting FIDO SVC");

	mainloop = g_main_loop_new(NULL, FALSE);

	__initialize();

	g_main_loop_run(mainloop);

	_INFO("Ending FIDO SVC");
	return 0;
}
