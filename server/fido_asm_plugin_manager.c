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

#include <app.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <gio/gio.h>

#include "fido_logs.h"
#include "fido_uaf_types.h"
#include "fido_internal_types.h"
#include "fido_json_handler.h"
#include "fido_internal_types.h"

#include "fido_asm_plugin_manager.h"

#define _ASM_CONF_DIR_PATH "/usr/lib/fido/asm/"

typedef struct _asm_ipc_cb_data {
    _asm_ipc_response_cb cb;
    void *user_data;
} _asm_ipc_cb_data_t;

typedef struct _asm_ipc_discover_cb_data {
    _asm_plugin_discover_response_cb cb;
    GList *asm_proxy_list_iter;
    void *user_data;
    GList *asm_resp_list;
} _asm_ipc_discover_cb_data_t;

static GHashTable *asm_proxy_table = NULL;
static GFileMonitor *__monitor = NULL;

static GDBusConnection *
__get_dbus_connection(void)
{
    GError *error = NULL;

    GDBusConnection *dbus_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);

    if (dbus_conn == NULL) {
        _ERR("Unable to connect to dbus: %s", error->message);
        g_clear_error(&error);
    }

    return dbus_conn;
}

static GDBusProxy*
__get_dbus_proxy(const char *dbus_name, const char *obj_path,
                 const char *intf_name)
{
    GDBusConnection *conn = __get_dbus_connection();
    if (conn == NULL)
        return NULL;

    GError *err = NULL;

    GDBusProxy *dbus_proxy = g_dbus_proxy_new_sync(conn,
                                        G_DBUS_PROXY_FLAGS_NONE,
                                        NULL,
                                        dbus_name,
                                        obj_path,
                                        intf_name,
                                        NULL,
                                        &err);

    if (err != NULL)
        _ERR("g_dbus_proxy_new_sync failed [%d][%s]", err->code, err->message);

    return dbus_proxy;
}

static void
__free_asm_proxy_data(gpointer data)
{
    if (data != NULL) {
        _fido_asm_proxy_t *proxy = data;

        SAFE_DELETE(proxy->bin_path);
        SAFE_DELETE(proxy->dbus_info);
        SAFE_DELETE(proxy->dbus_interface_name);
        SAFE_DELETE(proxy->dbus_method_name);
        SAFE_DELETE(proxy->dbus_obj_path);
        SAFE_DELETE(proxy->vendor);

        SAFE_DELETE(proxy);
    }


}

static int
__load_plugins(const char *path)
{
    RET_IF_FAIL(path != NULL, FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR);

    if (asm_proxy_table != NULL) {
        g_hash_table_destroy(asm_proxy_table);
        asm_proxy_table = NULL;
    }

    asm_proxy_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, _free_fido_asm_proxy);

    DIR *dir;
    struct dirent *entry;

    dir = opendir(path);
    if (dir == NULL) {

        _ERR("Could not open [%s] path = [%s]", path, strerror(errno));
        return FIDO_ERROR_PERMISSION_DENIED;
    }

    bool is_asm_found = false;

    _INFO("Loading ASM conf files");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char *conf_file_name = entry->d_name;
            if (conf_file_name != NULL) {
                char conf_file_name_full[128] = {0, };
                /*TODO make safe size*/
                snprintf(conf_file_name_full, 127, "%s%s", _ASM_CONF_DIR_PATH, conf_file_name);
                _INFO("Processing [%s]", conf_file_name_full);
                _fido_asm_proxy_t *asm_proxy = _parse_asm_conf_file(conf_file_name_full);
                if (asm_proxy != NULL) {
                    asm_proxy->dbus_proxy = __get_dbus_proxy(asm_proxy->dbus_info, asm_proxy->dbus_obj_path,
                                                             asm_proxy->dbus_interface_name);
                    if (asm_proxy->dbus_proxy != NULL) {
                        is_asm_found = true;

                        asm_proxy->asm_id = strdup(conf_file_name);
                        g_hash_table_insert(asm_proxy_table, strdup(conf_file_name), asm_proxy);
                    }
                    else {
                        _ERR("Failed to get dbus proxy for the ASM");
                        __free_asm_proxy_data((gpointer)asm_proxy);
                    }
                }

            }
        }
    }

    closedir(dir);

    if (is_asm_found == false)
        return FIDO_ERROR_NOT_SUPPORTED;

    return FIDO_ERROR_NONE;
}

static void
__plugin_changed_cb(GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event_type,
               void* user_data)
{
    int ret = __load_plugins(_ASM_CONF_DIR_PATH);
    _INFO("__load_plugins=[%d]", ret);
}

static void
__set_up_watcher(const char *watch_path)
{
    if ((watch_path == NULL)
            || (strlen(watch_path) == 0))
        return;

    GFile* file = g_file_new_for_path(watch_path);

    if (__monitor != NULL)
        g_object_unref(__monitor);

    __monitor = g_file_monitor(file, G_FILE_MONITOR_NONE, NULL, NULL);
    g_object_unref(file);

    if (__monitor == NULL)
        return;

    g_signal_connect(__monitor, "changed", G_CALLBACK(__plugin_changed_cb), NULL);
}

int
_asm_plugin_mgr_init(void)
{

    _INFO("_asm_plugin_mgr_init start");

    int ret = __load_plugins(_ASM_CONF_DIR_PATH);
    _INFO("__load_plugins=[%d]", ret);

    __set_up_watcher(_ASM_CONF_DIR_PATH);

    /*Ignored load_plugins error, since ASM might get installed later*/
    return FIDO_ERROR_NONE;
}

void
_asm_plugin_mgr_destroy(void)
{
    if (asm_proxy_table != NULL) {
        g_hash_table_destroy(asm_proxy_table);
        asm_proxy_table = NULL;
    }
    if (__monitor != NULL)
        g_object_unref(__monitor);
}

static void
__discover_cb_internal(int error_code, const char *asm_response_json, void *user_data)
{
    _asm_ipc_discover_cb_data_t *cb_data = user_data;

    _asm_discover_response_t *response_info = calloc(1, sizeof(_asm_discover_response_t));
    response_info->error_code = error_code;
    if (asm_response_json != NULL)
        response_info->asm_response_json = strdup(asm_response_json);

    _fido_asm_proxy_t *asm_proxy = (_fido_asm_proxy_t*)(cb_data->asm_proxy_list_iter->data);
    response_info->asm_id = strdup(asm_proxy->asm_id);

    cb_data->asm_resp_list = g_list_append(cb_data->asm_resp_list, response_info);

    cb_data->asm_proxy_list_iter = g_list_next(cb_data->asm_proxy_list_iter);
    if (cb_data->asm_proxy_list_iter == NULL) {
        _INFO("All ASM processing finished");

        cb_data->asm_resp_list = g_list_first(cb_data->asm_resp_list);
        (cb_data->cb)(cb_data->asm_resp_list, cb_data->user_data);

        cb_data->asm_proxy_list_iter = g_list_first(cb_data->asm_proxy_list_iter);
        g_list_free(cb_data->asm_proxy_list_iter);

        SAFE_DELETE(cb_data);
    }
    else {

        _fido_asm_proxy_t *asm_proxy = (_fido_asm_proxy_t*)(cb_data->asm_proxy_list_iter->data);
        int ret = _asm_ipc_send(asm_proxy->asm_id, _GET_INFO_ASM_REQUEST_JSON, __discover_cb_internal, cb_data);
        if (ret != FIDO_ERROR_NONE)
            __discover_cb_internal(ret, NULL, user_data);
    }

}

int
_asm_plugin_mgr_discover_all(_asm_plugin_discover_response_cb cb, void *user_data)
{
    if (asm_proxy_table == NULL
            || g_hash_table_size(asm_proxy_table) <= 0) {
        _ERR("No ASM found");
        return FIDO_ERROR_NOT_SUPPORTED;
    }

    _asm_ipc_discover_cb_data_t *cb_data = calloc(1, sizeof(_asm_ipc_discover_cb_data_t));
    if (cb_data == NULL)
        return -1;

    cb_data->cb = cb;
    cb_data->asm_proxy_list_iter = g_hash_table_get_values(asm_proxy_table);

    cb_data->user_data = user_data;

    _fido_asm_proxy_t *asm_proxy = (_fido_asm_proxy_t*)(cb_data->asm_proxy_list_iter->data);

    return _asm_ipc_send(asm_proxy->asm_id, _GET_INFO_ASM_REQUEST_JSON, __discover_cb_internal, cb_data);
}

static void
_on_asm_dbus_reply(GObject *proxy, GAsyncResult *res, gpointer user_data)
{
    _INFO("_on_asm_dbus_reply");

    GError *dbus_err = NULL;

    if (user_data == NULL) {
        _ERR("Can not proceed since callback data is NULL");
        return;
    }

    _asm_ipc_cb_data_t *cb_data = (_asm_ipc_cb_data_t *)user_data;
    if (cb_data == NULL) {
        _ERR("Can not proceed since callback data is NULL");
        return;
    }

    if (cb_data->cb == NULL) {
        _ERR("Can not proceed since callback data's cb part is NULL");
        return;
    }

    int tizen_err = FIDO_ERROR_NONE;
    char *asm_response_json = NULL;

    GError *error = NULL;

    /*For dereg request, ASM does not send any reponse, so this is not error for dereg*/
    GVariant *dbus_resp = g_dbus_proxy_call_finish(G_DBUS_PROXY(proxy), res, &error);
    if (dbus_resp == NULL) {
        _ERR("g_dbus_proxy_call_finish failed  with [%d][%s]", error->code, error->message);
        (cb_data->cb)(FIDO_ERROR_PERMISSION_DENIED, NULL, cb_data->user_data);

        SAFE_DELETE(cb_data);

        return;
    }

    g_variant_get(dbus_resp, "(is)",
                   &tizen_err,
                   &asm_response_json);


    g_clear_error(&dbus_err);

    if (asm_response_json != NULL)
        _INFO("asm_response_json=[%s]", asm_response_json);

    (cb_data->cb)(tizen_err, asm_response_json, cb_data->user_data);

    if (dbus_resp != NULL)
        g_variant_unref(dbus_resp);

    SAFE_DELETE(cb_data);
}

static char*
__get_asm_req_dbus_method_name(const char *intf_name, const char *dbus_method_name)
{
    char *method_name = (char *)calloc(1, 128);
    if (method_name == NULL)
        return NULL;

    snprintf(method_name, 127, "%s.%s", intf_name, dbus_method_name);

    return method_name;
}

int
_asm_ipc_send(const char *asm_id, const char *asm_request, _asm_ipc_response_cb cb, void *user_data)
{
    _INFO("asm_request=[%s]", asm_request);

    if (asm_id == NULL) {
        _ERR("dbus proxy failed");
        return FIDO_ERROR_NOT_SUPPORTED;
    }

    _fido_asm_proxy_t *asm_proxy = g_hash_table_lookup(asm_proxy_table, asm_id);
    if (asm_proxy == NULL) {
        _ERR("dbus proxy failed");
        return FIDO_ERROR_NOT_SUPPORTED;
    }

    _INFO("For=[%s]", asm_id);

    if (asm_proxy->dbus_info != NULL)
        _INFO("For DBUS = [%s]", asm_proxy->dbus_info);

    _asm_ipc_cb_data_t *cb_data = (_asm_ipc_cb_data_t*)calloc(1, sizeof(_asm_ipc_cb_data_t));
    if (cb_data == NULL)
        return -1;

    cb_data->cb = cb;
    cb_data->user_data = user_data;

    char *method_name = __get_asm_req_dbus_method_name(asm_proxy->dbus_interface_name,
                                                       asm_proxy->dbus_method_name);
    if (method_name == NULL) {

        SAFE_DELETE(cb_data);
        return FIDO_ERROR_OUT_OF_MEMORY;
    }

    g_dbus_proxy_call(asm_proxy->dbus_proxy,
                        method_name,
                        g_variant_new ("(s)",
                        asm_request),
                        G_DBUS_CALL_FLAGS_NONE,
                        _DBUS_TIMEOUT_INFINITE,
                        NULL,
                        _on_asm_dbus_reply,
                        cb_data);

    SAFE_DELETE(method_name);

    return 0;
}

char *
_asm_ipc_send_sync(const char *asm_id, const char *asm_req)
{
    _INFO("_asm_ipc_send_sync");

    if (asm_id == NULL) {
        _ERR("dbus proxy failed");
        return NULL;
    }

    _INFO("For=[%s]", asm_id);

    _fido_asm_proxy_t *asm_proxy = g_hash_table_lookup(asm_proxy_table, asm_id);
    if (asm_proxy == NULL) {
        _ERR("dbus proxy failed");
        return NULL;
    }

    if (asm_proxy->dbus_info != NULL)
        _INFO("For DBUS = [%s]", asm_proxy->dbus_info);

    int tz_err = FIDO_ERROR_NONE;
    char *asm_res_json = NULL;

    GError *error = NULL;
    GVariant *_ret;

    char *method_name = __get_asm_req_dbus_method_name(asm_proxy->dbus_interface_name,
                                                       asm_proxy->dbus_method_name);

    if (method_name == NULL)
        return NULL;

    _ret = g_dbus_proxy_call_sync(asm_proxy->dbus_proxy,
                                  method_name,
                                  g_variant_new ("(s)",
                                  asm_req),
                                  G_DBUS_CALL_FLAGS_NONE,
                                  _DBUS_TIMEOUT_USE_DEFAULT,
                                  NULL,
                                  &error);

    if (error != NULL)
        _ERR("g_dbus_proxy_call_sync failed [%s]", error->message);
    else
        _INFO("g_dbus_proxy_call_sync success");

    if (_ret == NULL)
      goto CATCH;

    g_variant_get (_ret, "(is)", &tz_err, &asm_res_json);
    if (asm_res_json != NULL)
        _INFO("ASM returned = %s", asm_res_json);

    //g_variant_unref (_ret);

CATCH:
    return asm_res_json;
}
