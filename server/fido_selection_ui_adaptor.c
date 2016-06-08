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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <glib.h>
#include <json-glib/json-glib.h>
#include <app.h>
#include <aul.h>
#include <bundle.h>

#include "fido_selection_ui_adaptor.h"
#include "fido_uaf_types.h"
#include "fido_logs.h"
#include "fido-stub.h"
#include "fido_internal_types.h"

#define _UI_LAUNCH_RETRY_COUNT 5
#define _UI_SVC_TERMINATE_TIMEOUT 2000

#define _FREEDESKTOP_SERVICE    "org.freedesktop.DBus"
#define _FREEDESKTOP_PATH       "/org/freedesktop/DBus"
#define _FREEDESKTOP_INTERFACE  "org.freedesktop.DBus"

static GQueue *_ui_q = NULL;
static int __ui_svc_pid = -1;

static int _process_ui_selection_queue(void);

typedef struct _ui_response_cb_data {
	GList *auth_list;
	_ui_response_cb cb;
	void *user_data;
} _ui_response_cb_data_t;

static void
__free_ui_auth_data(gpointer data)
{
	RET_IF_FAIL_VOID(data != NULL);

	_ui_auth_data_t *auth_data = data;

	SAFE_DELETE(auth_data->asm_id);
	SAFE_DELETE(auth_data->auth_index);
	SAFE_DELETE(auth_data->label);

	SAFE_DELETE(auth_data);
}

static void
__free_ui_response_cb_data(_ui_response_cb_data_t *data)
{
	RET_IF_FAIL_VOID(data != NULL);

	if (data->auth_list != NULL)
		g_list_free_full(data->auth_list, __free_ui_auth_data);

	SAFE_DELETE(data);
}

static GQueue *
_get_ui_queue(void)
{
	if (_ui_q != NULL)
		return _ui_q;

	_ui_q = g_queue_new();
	if (_ui_q == NULL)
		_ERR("Out of memory");

	return _ui_q;
}

_ui_auth_data_t*
_compose_json_ui_out(const char *response_json)
{
	_INFO("_compose_json_ui_out %s", response_json);

	char *ui_response_json = strdup(response_json);
	_ui_auth_data_t *ui_auth_data = NULL;
	GError *parse_err = NULL;
	JsonParser *parser = NULL;
	JsonNode *root = NULL;
	JsonObject *obj = NULL;

	parser = json_parser_new();
	if (!parser) {
		_ERR("json_parser_new failed");
		goto CATCH;
	}

	json_parser_load_from_data(parser, ui_response_json, -1, &parse_err);
	if (parse_err != NULL) {
		_ERR("json parse failure");
		goto CATCH;
	}

	root = json_parser_get_root(parser);
	if (!root) {
		_ERR("json_parser_get_root() failed");
		goto CATCH;
	}

	obj = json_node_get_object(root);
	if (!obj) {
		_ERR("json_node_get_object() failed");
		goto CATCH;
	}

	const char *asm_id = json_object_get_string_member(obj, UI_DATA_ASM_ID);
	if (!asm_id) {
		_ERR("json_object_get_string_member() failed");
		goto CATCH;
	}

	const char *auth_idx = NULL;
	auth_idx = json_object_get_string_member(obj, UI_DATA_AUTH_INDEX);
	if (!auth_idx) {
		_ERR("json_object_get_string_member() failed");
		goto CATCH;
	}

	const char *label = NULL;
	label = json_object_get_string_member(obj, UI_DATA_LABEL);
	if (!label) {
		_ERR("json_object_get_string_member() failed");
		goto CATCH;
	}

	int att = -1;
	att = json_object_get_int_member(obj, UI_DATA_ATT_TYPE);

	ui_auth_data = (_ui_auth_data_t *) calloc(1, sizeof(_ui_auth_data_t));
	if (ui_auth_data == NULL) {
		_ERR("Out of memory");
		goto CATCH;
	}

	ui_auth_data->asm_id = strdup(asm_id);
	ui_auth_data->auth_index = strdup(auth_idx);
	ui_auth_data->label = strdup(label);
	ui_auth_data->att_type = att;

CATCH:
	if (parse_err != NULL) {
		g_error_free(parse_err);
		parse_err = NULL;
	}

	if (root != NULL) {
		json_node_free(root);
		root = NULL;
	}

	if (obj != NULL) {
		g_object_unref(obj);
		obj = NULL;
	}

	SAFE_DELETE(ui_response_json);

	return ui_auth_data;
}

char *
_compose_json_ui_in(GList *auth_list)
{
	_INFO("_compose_json_ui_in");

	char *json_ui_arr = NULL;
	JsonGenerator *generator = NULL;
	JsonNode *root_node = NULL;
	JsonArray *ui_arr = NULL;

	generator = json_generator_new();
	if (generator == NULL) {
		_ERR("json_generator_new is NULL");
		goto CATCH;
	}

	root_node = json_node_new(JSON_NODE_ARRAY);
	if (root_node == NULL) {
		_ERR("json_node_new is NULL");
		goto CATCH;
	}

	ui_arr = json_array_new();
	if (ui_arr == NULL) {
		_ERR("json_array_new is NULL");
		goto CATCH;
	}

	json_node_take_array(root_node, ui_arr);
	json_generator_set_root(generator, root_node);

	GList *auth_list_iter = auth_list;
	while (auth_list_iter != NULL) {
		_ui_auth_data_t *ui_data = (_ui_auth_data_t *)(auth_list_iter->data);

		if (ui_data) {
			JsonObject *obj = json_object_new();

			if (ui_data->asm_id != NULL)
				json_object_set_string_member(obj, UI_DATA_ASM_ID, ui_data->asm_id);

			json_object_set_string_member(obj, UI_DATA_AUTH_INDEX, ui_data->auth_index);
			if (ui_data->label != NULL)
				json_object_set_string_member(obj, UI_DATA_LABEL, ui_data->label);
			json_object_set_int_member(obj, UI_DATA_ATT_TYPE, ui_data->att_type);

			json_array_add_object_element(ui_arr, obj);
		}

		auth_list_iter = auth_list_iter->next;
	}

	json_ui_arr = json_generator_to_data(generator, NULL);

CATCH:
	if (generator != NULL) {
		g_object_unref(generator);
		generator = NULL;
	}

	if (root_node != NULL) {
		json_node_free(root_node);
		root_node = NULL;
	}

	if (ui_arr != NULL) {
		json_array_unref(ui_arr);
		ui_arr = NULL;
	}

	return json_ui_arr;
}

//static int
//__iterfunc(const aul_app_info *info, void *data)
//{
//    if (strcmp(info->pkg_name, _UI_SVC_PACKAGE) == 0) {
//        aul_terminate_pid(info->pid);
//        _INFO("After aul_terminate_pid");
//        return false;
//    }
//    return true;
//}

static void
__terminate_ui_svc(void)
{
	_INFO("Killing inactive UI Service [%d]", __ui_svc_pid);

	if (__ui_svc_pid > 0)
		aul_terminate_pid(__ui_svc_pid);

	__ui_svc_pid = -1;
}

static gboolean
__timer_expired(gpointer data)
{
	if (g_queue_is_empty(_ui_q) == TRUE)
		__terminate_ui_svc();

	return FALSE;
}

static void
__start_ui_svc_term_timer(void)
{
	g_timeout_add(_UI_SVC_TERMINATE_TIMEOUT, __timer_expired, NULL);
}

static int
__launch_svc_ui(bundle *ui_req)
{
	int i = 0;
	for (; i < _UI_LAUNCH_RETRY_COUNT; i++) {
		if (__ui_svc_pid < 0)
			__ui_svc_pid = aul_launch_app(_UI_SVC_PACKAGE, ui_req);
		else {
			aul_terminate_pid(__ui_svc_pid);
			__ui_svc_pid = -1;

			__ui_svc_pid = aul_launch_app(_UI_SVC_PACKAGE, ui_req);
		}

		_INFO("fido svc pid = [%d]", __ui_svc_pid);

		if (__ui_svc_pid > 0)
			return FIDO_ERROR_NONE;
	}
	return FIDO_ERROR_UNKNOWN;
}

static int
_process_ui_selection_queue(void)
{
	_INFO("_process_ui_selection_queue");
	GQueue *q = _ui_q;
	RET_IF_FAIL(q, FIDO_ERROR_INVALID_PARAMETER);

	if (g_queue_is_empty(q) == true)
		return FIDO_ERROR_NONE;

	_ui_response_cb_data_t *ui_res_data = (_ui_response_cb_data_t *)(g_queue_peek_head(q));
	RET_IF_FAIL(ui_res_data, FIDO_ERROR_INVALID_PARAMETER);

	char *ui_data = _compose_json_ui_in(ui_res_data->auth_list);
	if (ui_data == NULL) {
		ui_res_data->cb(FIDO_ERROR_OUT_OF_MEMORY, NULL, ui_res_data->user_data);
		g_queue_pop_head(q);
		return FIDO_ERROR_OUT_OF_MEMORY;
	}

	_INFO("Sending to UI SVC");
	_INFO("%s", ui_data);

	bundle *ui_req = bundle_create();
	bundle_add_str(ui_req, _UI_IPC_KEY_REQ, ui_data);

	return __launch_svc_ui(ui_req);
}

int
_auth_ui_selector_send(GList *auth_list, _ui_response_cb cb, void *user_data)
{
	_INFO("_auth_ui_selector_send");
	RET_IF_FAIL(auth_list, FIDO_ERROR_INVALID_PARAMETER);

	_ui_response_cb_data_t *ui_cb_data = (_ui_response_cb_data_t *) calloc(1, sizeof(_ui_response_cb_data_t));
	RET_IF_FAIL(ui_cb_data, FIDO_ERROR_OUT_OF_MEMORY);

	ui_cb_data->auth_list = auth_list;
	ui_cb_data->cb = cb;
	ui_cb_data->user_data = user_data;

	GQueue *q = _get_ui_queue();
	if (q == NULL) {
		__free_ui_response_cb_data(ui_cb_data);
		return FIDO_ERROR_OUT_OF_MEMORY;
	}

	g_queue_push_tail(q, ui_cb_data);
	_INFO("Q len=[%d]", g_queue_get_length(q));

	if (g_queue_get_length(q) == 1)
		_process_ui_selection_queue();

	return FIDO_ERROR_NONE;
}

static inline int
__read_proc(const char *path, char *buf, int size)
{
	int fd = 0;
	int ret = 0;

	if (buf == NULL || path == NULL) {
		_ERR("path and buffer is mandatory\n");
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		_ERR("fd open error(%d)\n", fd);
		return -1;
	}

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		_ERR("fd read error(%d)\n", fd);
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

static char*
__get_proc_path_of_dbus_caller(GDBusMethodInvocation *invocation)
{
	//pid_t remote_pid = 0;
	GError *error = NULL;
	GDBusConnection *connection = NULL;
	GVariant *response = NULL;
	guint32 upid;
	const gchar *sender = NULL;

	sender = g_dbus_method_invocation_get_sender(invocation);
	if (!sender) {
		_ERR("Failed to get sender");
		return NULL;
	}

	connection = g_dbus_method_invocation_get_connection(invocation);
	if (connection == NULL) {
		_ERR("Failed to open connection for the invocation [%s]", error->message);
		g_error_free(error);
		return NULL;
	}

	error = NULL;
	response = g_dbus_connection_call_sync(connection,
				_FREEDESKTOP_SERVICE, _FREEDESKTOP_PATH,
				_FREEDESKTOP_INTERFACE, "GetConnectionUnixProcessID",
				g_variant_new("(s)", sender), ((const GVariantType *) "(u)"),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (response == NULL) {
		_ERR("Failed to get caller id [%s]", error->message);
		g_error_free(error);
		return NULL;
	}

	g_variant_get(response, "(u)", &upid);
	_INFO("Remote msg-bus peer service=%s pid=%u", sender, upid);
	//remote_pid = (pid_t) upid;

	g_variant_unref(response);

	char buf[128];
	int ret = 0;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", upid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0) {
		_ERR("No proc directory (%d)\n", upid);
		return NULL;
	}

	_INFO("Caller=[%s]", buf);

	return strdup(buf);
}

gboolean
_auth_ui_selector_on_ui_response(Fido *object, GDBusMethodInvocation *invocation, int error, const char *ui_resp)
{
	_INFO("");

	char *caller = __get_proc_path_of_dbus_caller(invocation);
	if (caller == NULL) {
		_ERR("__get_proc_path_of_dbus_caller failed");
		__start_ui_svc_term_timer();
		return true;
	}

	if (strcmp(caller, _UI_SVC_BIN_PATH) != 0) {
		_ERR("[%s] is not allowed", caller);
		__start_ui_svc_term_timer();
		return true;
	}

	_ui_response_cb_data_t *cb_data = (_ui_response_cb_data_t*)(g_queue_pop_head(_ui_q));
	if (cb_data == NULL) {
		_ERR("Can not proceed since callback data is NULL");
		goto CATCH;
	}

	if (cb_data->cb == NULL) {
		_ERR("Can not proceed since callback data's cb part is NULL");
		goto CATCH;
	}

	if (error != FIDO_ERROR_NONE)
		cb_data->cb(error, NULL, cb_data->user_data);
	else {
		if (ui_resp == NULL)
			cb_data->cb(FIDO_ERROR_PERMISSION_DENIED, NULL, cb_data->user_data);
		else {
			_INFO("response from server = [%s]", ui_resp);

			_ui_auth_data_t *ui_auth_data = _compose_json_ui_out(ui_resp);
			cb_data->cb(FIDO_ERROR_NONE, ui_auth_data, cb_data->user_data);
		}
	}

CATCH:

	if (g_queue_is_empty(_ui_q) == false)
		_process_ui_selection_queue();
	else {
		g_queue_free(_ui_q);
		_ui_q = NULL;
		__start_ui_svc_term_timer();
	}

	return true;
}
