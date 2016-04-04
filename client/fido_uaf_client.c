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

#include "fido_uaf_client.h"
#include "fido_logs.h"
#include "fido_internal_types.h"
#include "fido_json_handler.h"
#include "fido-stub.h"
#include "fido_keys.h"
#include "fido_uaf_authenticator.h"

static Fido *_fido_dbus_obj = NULL;

typedef struct _fido_process_cb_data {
    fido_uaf_response_message_cb cb;
    void *user_data;
} _fido_process_cb_data_s;


static void
init_dbus(void)
{
    _INFO("init_dbus");
#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif

    GDBusConnection *connection = NULL;
    GError *error = NULL;

    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);

    _INFO("after g_bus_get_sync");


    /* Create the object */
    _fido_dbus_obj = fido_proxy_new_sync(connection,
                                         G_DBUS_PROXY_FLAGS_NONE,
                                         _FIDO_DBUS_NAME,
                                         _FIDO_DBUS_PATH,
                                         NULL,
                                         &error);
}

Fido *
_dbus_proxy_get_instance(int time_out)
{
    _INFO("_dbus_proxy_get_instance singleton");

    static pthread_once_t onceBlock = PTHREAD_ONCE_INIT;
    if (_fido_dbus_obj == NULL) {
        pthread_once(&onceBlock, init_dbus);
        if (_fido_dbus_obj == NULL) {
            _ERR("init_dbus failed");
            onceBlock = PTHREAD_ONCE_INIT;
        }
    }
    _INFO("_dbus_proxy_get_instance end");

    g_dbus_proxy_set_default_timeout(G_DBUS_PROXY(_fido_dbus_obj), time_out);

    return _fido_dbus_obj;
}

static void
_fido_uaf_process_operation_reply(GObject *object, GAsyncResult *res, gpointer user_data)
{
    _INFO("_fido_uaf_process_operation_reply");

    GError *dbus_err = NULL;

    if (user_data == NULL) {
        _ERR("Can not proceed since callback data is NULL");
        return;
    }

    _fido_process_cb_data_s *cb_data = (_fido_process_cb_data_s *)user_data;
    if (cb_data == NULL) {
        _ERR("Can not proceed since callback data is NULL");
        return;
    }

    if (cb_data->cb == NULL) {
        _ERR("Can not proceed since callback data's cb part is NULL");
        SAFE_DELETE(cb_data);
        return;
    }

    int tizen_err = FIDO_ERROR_NONE;

    char *uaf_response_json = NULL;

    fido_call_fido_uaf_process_operation_finish(_fido_dbus_obj, &tizen_err, &uaf_response_json,
                                           res, &dbus_err);

    if (dbus_err) {
        _ERR("fido_foreach_authenticator failed [%s]", dbus_err->message);
        if (tizen_err == FIDO_ERROR_NONE)
            tizen_err = FIDO_ERROR_PERMISSION_DENIED;
        /* Error is notified via tizen_err and/or fido_err, so no need to get dbus error*/
    }

    g_clear_error(&dbus_err);

    if (strcmp(uaf_response_json, _EMPTY_JSON_STRING) == 0)
        (cb_data->cb)(tizen_err, NULL, cb_data->user_data);
    else
        (cb_data->cb)(tizen_err, uaf_response_json, cb_data->user_data);

    _INFO("After calling fido_uaf_response_message_cb");

    SAFE_DELETE(cb_data);
    SAFE_DELETE(uaf_response_json);
}

EXPORT_API int
fido_foreach_authenticator(fido_authenticator_cb callback, void *user_data)
{
    if (callback == NULL) {
        _ERR("callback can not be NULL [FIDO_ERROR_INVALID_PARAMETER]");
        return FIDO_ERROR_INVALID_PARAMETER;
    }

    Fido *dbus_proxy = _dbus_proxy_get_instance(_DBUS_TIMEOUT_USE_DEFAULT);
    if (dbus_proxy == NULL) {
        _ERR("DBus proxy failed");
        return FIDO_ERROR_NOT_SUPPORTED;
    }

	gchar **discovery_data_json = NULL;
	int discovery_data_json_list_len = 0;
	int tz_err = 0;
	GError *dbus_err = NULL;
	fido_call_fido_uaf_discover_sync(dbus_proxy, &tz_err, &discovery_data_json, &discovery_data_json_list_len,
									 NULL, &dbus_err);


	if (dbus_err != NULL) {
		_ERR("fido_call_fido_uaf_discover_sync failed [%s]", dbus_err->message);
		g_clear_error(&dbus_err);

		return FIDO_ERROR_PERMISSION_DENIED;
	}

	if (discovery_data_json == NULL || discovery_data_json_list_len <= 0) {
		_ERR("No Authenticators found");
		return FIDO_ERROR_NOT_SUPPORTED;
	}

	_INFO("ASM response len =[%d]", discovery_data_json_list_len);

	tz_err = FIDO_ERROR_NONE;

	int parser_err = 0;
	GList *auth_list = _uaf_parser_parse_asm_response_discover_client(discovery_data_json,
																		  discovery_data_json_list_len, &parser_err);
	if (parser_err != FIDO_ERROR_NONE) {
		tz_err = _convert_asm_status_code_to_uaf_error(parser_err);
	} else {

		if (g_list_length(auth_list) <= 0) {
			tz_err = FIDO_ERROR_NOT_SUPPORTED;
		} else {

			GList *auth_list_iter = g_list_first(auth_list);
			while (auth_list_iter != NULL) {

				fido_authenticator_s *auth_priv = (fido_authenticator_s *)(auth_list_iter->data);
				(callback)((fido_authenticator_h)auth_priv, user_data);
				auth_list_iter = auth_list_iter->next;
			}
		}
	}

	int i = 0;
	for (; i < discovery_data_json_list_len; i++)
		SAFE_DELETE(discovery_data_json[i]);

	SAFE_DELETE(discovery_data_json);

	/*Items are deleted after callback is done for elements, so apps must make a local copy of elements if they
	  want to use them later*/
	g_list_free_full(auth_list, _free_asm_auth_list);

	return tz_err;
}

EXPORT_API int
fido_get_client_vendor(char **vendor_name)
{
	if (vendor_name == NULL)
		return FIDO_ERROR_INVALID_PARAMETER;

	char *vn_temp = (char*)calloc(1, _CLIENT_VENDOR_NAME_MAX_SIZE + 1);
	strncpy(vn_temp, _CLIENT_VENDOR_NAME, _CLIENT_VENDOR_NAME_MAX_SIZE);

	*vendor_name = vn_temp;

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_get_client_version(int *client_major_version, int *client_minor_version)
{
	if ((client_major_version == NULL) || (client_minor_version == NULL))
		return FIDO_ERROR_INVALID_PARAMETER;

	*client_major_version = _CLIENT_VERSION_MAJOR;
	*client_minor_version = _CLIENT_VERSION_MINOR;

	return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_uaf_is_supported(const char *uaf_message_json, bool *is_supported)
{
    if (uaf_message_json == NULL) {
        _ERR("uaf_message_json can not be NULL [FIDO_ERROR_INVALID_PARAMETER]");
        return FIDO_ERROR_INVALID_PARAMETER;
    }

    Fido *dbus_proxy = _dbus_proxy_get_instance(_DBUS_TIMEOUT_USE_DEFAULT);
    if (dbus_proxy == NULL) {
        _ERR("DBus proxy failed");
        return FIDO_ERROR_NOT_SUPPORTED;
    }

	int tz_err = FIDO_ERROR_NONE;
	GError *dbus_err = NULL;
	fido_call_fido_uaf_check_policy_sync(dbus_proxy, uaf_message_json, &tz_err,
										 NULL, &dbus_err);

	if (dbus_err != NULL) {
		_ERR("fido_call_fido_uaf_check_policy_sync failed [%s]", dbus_err->message);
		g_clear_error(&dbus_err);
		return FIDO_ERROR_PERMISSION_DENIED;
	}

	if (tz_err == FIDO_ERROR_NONE)
		*is_supported = true;
	else
		*is_supported = false;

    return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_uaf_get_response_message(const char *uaf_request_json, const char *channel_binding_json,
                           fido_uaf_response_message_cb callback, void *user_data)
{
    if (callback == NULL) {
        _ERR("callback can not be NULL [FIDO_ERROR_INVALID_PARAMETER]");
        return FIDO_ERROR_INVALID_PARAMETER;
    }
    if (uaf_request_json == NULL) {
        _ERR("uaf_request_json can not be NULL [FIDO_ERROR_INVALID_PARAMETER]");
        return FIDO_ERROR_INVALID_PARAMETER;
    }

    Fido *dbus_proxy = _dbus_proxy_get_instance(_DBUS_TIMEOUT_INFINITE);
    if (dbus_proxy == NULL) {
        _ERR("DBus proxy failed");
        return FIDO_ERROR_NOT_SUPPORTED;
    }

    _fido_process_cb_data_s *cb_data = (_fido_process_cb_data_s *) calloc(1, sizeof(_fido_process_cb_data_s));
    cb_data->cb = callback;
    cb_data->user_data = user_data;

    if (channel_binding_json != NULL) {
		fido_call_fido_uaf_process_operation(dbus_proxy, uaf_request_json, channel_binding_json,
                                             NULL, _fido_uaf_process_operation_reply, cb_data);
    } else {
		fido_call_fido_uaf_process_operation(dbus_proxy, uaf_request_json,
											 _FIDO_NO_CHANNEL_BINDING_DBUS_STRING,
                                             NULL, _fido_uaf_process_operation_reply, cb_data);
	}

    return FIDO_ERROR_NONE;
}

EXPORT_API int
fido_uaf_set_server_result(int response_code, const char *uaf_response_json)
{
    if (uaf_response_json == NULL) {
        _ERR("uaf_response_json can not be NULL [FIDO_ERROR_INVALID_PARAMETER]");
        return FIDO_ERROR_INVALID_PARAMETER;
    }

    Fido *dbus_proxy = _dbus_proxy_get_instance(_DBUS_TIMEOUT_USE_DEFAULT);
    if (dbus_proxy == NULL) {
        _ERR("DBus proxy failed");
        return FIDO_ERROR_NOT_SUPPORTED;
    }

    GError *dbus_err = NULL;

    int tizen_error_code = FIDO_ERROR_NONE;

    _response_t *uaf_res_data = _uaf_parser_parse_uaf_response(uaf_response_json);
    if (uaf_res_data == NULL)
        return FIDO_ERROR_PROTOCOL_ERROR;

    if (response_code == FIDO_SERVER_STATUS_CODE_OK) {
        _free_response(uaf_res_data);
        return FIDO_ERROR_NONE;
    }


    _INFO("before checking operation name");
    if (strcmp(uaf_res_data->header->operation, _UAF_OPERATION_NAME_KEY_REG) != 0) {
        _free_response(uaf_res_data);
        return FIDO_ERROR_NONE;
    }

    /*Only for reg response, if not success code, then delete the reg*/

    _INFO("before calling _uaf_composer_compose_dereg_request");
    char *uaf_dereg_json = _uaf_composer_compose_dereg_request(uaf_res_data);

    _free_response(uaf_res_data);

    if (uaf_dereg_json == NULL)
        return FIDO_ERROR_PROTOCOL_ERROR;

    int tz_err = FIDO_ERROR_NONE;
    char *resp = 0;

    GError *err = NULL;
	gboolean is_success = fido_call_fido_uaf_process_operation_sync(dbus_proxy,
																	uaf_dereg_json,
                                                                    _FIDO_NO_CHANNEL_BINDING_DBUS_STRING, &tz_err,
                                                                    &resp, NULL, &err);

    if (is_success == FALSE) {
        _ERR("fido_call_fido_uaf_notify_result_sync failed [%d]", tizen_error_code);
        if (dbus_err) {
            _ERR("GError = [%s]", dbus_err->message);
        }
        return FIDO_ERROR_PROTOCOL_ERROR;
    }

    return tz_err;
}
