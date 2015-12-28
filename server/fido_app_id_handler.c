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
#include <unistd.h>
#include <libsoup/soup.h>
#include <app_manager.h>
#include <fido_uaf_types.h>
#include <string.h>

#include "fido_internal_types.h"
#include "fido_json_handler.h"
#include "fido_app_id_handler.h"
#include "fido_logs.h"

#define _FREEDESKTOP_SERVICE    "org.freedesktop.DBus"
#define _FREEDESKTOP_PATH       "/org/freedesktop/DBus"
#define _FREEDESKTOP_INTERFACE  "org.freedesktop.DBus"

#define _MAX_NW_TIME_OUT 20

typedef struct _app_id_cb_data {
    char *caller_app_id;
    char *real_app_id;
    _facet_id_cb cb;
    void *user_data;
}_app_id_cb_data_t;

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
__get_appid_of_dbus_caller(GDBusMethodInvocation *invocation)
{
    pid_t remote_pid = 0;
    GError *error = NULL;
    GDBusConnection *connection = NULL;
    GVariant *response = NULL;
    guint32 upid;
    const gchar *sender = NULL;

    sender = g_dbus_method_invocation_get_sender (invocation);
    if (!sender) {
        _ERR("Failed to get sender");
        return NULL;
    }

    connection = g_dbus_method_invocation_get_connection(invocation);
    if (connection == NULL) {
        _ERR("Failed to open connection for the invocation");
        return NULL;
    }

    error = NULL;
    response = g_dbus_connection_call_sync (connection,
            _FREEDESKTOP_SERVICE, _FREEDESKTOP_PATH,
            _FREEDESKTOP_INTERFACE, "GetConnectionUnixProcessID",
            g_variant_new ("(s)", sender), ((const GVariantType *) "(u)"),
            G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

    //g_object_unref (connection);

    if (response == NULL) {
        _ERR("Failed to get caller id [%s]", error->message);
        g_error_free (error);
        return NULL;
    }

    g_variant_get (response, "(u)", &upid);
    _INFO("Remote msg-bus peer service=%s pid=%u", sender, upid);
    remote_pid = (pid_t) upid;

    g_variant_unref (response);

    char *app_id = NULL;
    int ret = app_manager_get_app_id(remote_pid, &app_id);

    if (app_id == NULL) {
        _ERR("app_manager_get_app_id for %d failed = %d", remote_pid, ret);

        /* Exception case : Daemons will not have app-ids, for them path will be set : /usr/bin/sample-service */
        char buf[128];
        int ret = 0;

        snprintf(buf, sizeof(buf), "/proc/%d/cmdline", upid);
        ret = __read_proc(buf, buf, sizeof(buf));
        if (ret <= 0) {
            _ERR("No proc directory (%d)\n", upid);
            return NULL;
        }

        _INFO("Caller=[%s]", buf);

        app_id = strdup(buf);
    }


    return app_id;
}

static void
__soup_cb(SoupSession *session, SoupMessage *msg, gpointer user_data)
{
    _INFO("__soup_cb");

    if (user_data == NULL)
        return;

    _app_id_cb_data_t *cb_data = (_app_id_cb_data_t*)user_data;

    GList *app_id_list = NULL;
    char *real_app_id = NULL;

    int error_code = FIDO_ERROR_UNTRUSTED_FACET_ID;

    SoupBuffer *request = NULL;

    _INFO("status_code = [%d]", msg->status_code);

    CATCH_IF_FAIL_X(msg->status_code == SOUP_STATUS_OK, error_code = FIDO_ERROR_UNTRUSTED_FACET_ID);

    request = soup_message_body_flatten(msg->response_body);
    app_id_list = _uaf_parser_parse_trusted_facets(request->data);

    soup_buffer_free(request);
    request = NULL;

    if (app_id_list == NULL)
        error_code = FIDO_ERROR_UNTRUSTED_FACET_ID;

    GList *app_id_list_iter = app_id_list;
    while (app_id_list_iter != NULL) {
        char *id = (char *)(app_id_list_iter->data);
        SoupURI *parsed_uri = soup_uri_new(id);
        if (parsed_uri == NULL)
            if (strcmp(cb_data->caller_app_id, id) == 0) {
                real_app_id = strdup(id);
                error_code = FIDO_ERROR_NONE;
                break;
            }
        soup_uri_free(parsed_uri);

        app_id_list_iter = app_id_list_iter->next;
    }

CATCH:
    (cb_data->cb)(error_code, real_app_id, cb_data->user_data);

    if (app_id_list != NULL)
        g_list_free_full(app_id_list, free);

    SAFE_DELETE(real_app_id);
    SAFE_DELETE(cb_data->real_app_id);
    SAFE_DELETE(cb_data->caller_app_id);
    SAFE_DELETE(cb_data);
}

static void
_free_app_id_cb_data(_app_id_cb_data_t* data)
{
    _INFO("");

    RET_IF_FAIL_VOID(data != NULL);

    SAFE_DELETE(data->real_app_id);
    SAFE_DELETE(data->caller_app_id);

    SAFE_DELETE(data);

    _INFO("");
}

static gboolean
__timer_expired(gpointer data)
{
    _INFO("__timer_expired");
    _app_id_cb_data_t *cb_data = (_app_id_cb_data_t*)data;
    (cb_data->cb)(FIDO_ERROR_NONE, cb_data->real_app_id, cb_data->user_data);

    _free_app_id_cb_data(cb_data);

    return FALSE;
}

int
_verify_and_get_facet_id(const char *uaf_app_id, GDBusMethodInvocation *invocation, _facet_id_cb cb, void *user_data)
{
    _INFO("_verify_and_get_facet_id");

    char *app_id = __get_appid_of_dbus_caller(invocation);
    if (app_id == NULL) {
        return FIDO_ERROR_PERMISSION_DENIED;
    }

    _app_id_cb_data_t *cb_data = (_app_id_cb_data_t*)calloc(1, sizeof(_app_id_cb_data_t));
    if (cb_data == NULL)
        return FIDO_ERROR_OUT_OF_MEMORY;

    cb_data->caller_app_id = app_id;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    if (uaf_app_id == NULL) {
         cb_data->real_app_id = strdup(app_id);
         g_timeout_add(2, __timer_expired, cb_data);
         return FIDO_ERROR_NONE;
    }


    SoupURI *parsed_uri = soup_uri_new(uaf_app_id);

    if (parsed_uri == NULL) {

        if (strcmp(app_id, uaf_app_id) == 0) {
            cb_data->real_app_id = strdup(uaf_app_id);
            g_timeout_add(2, __timer_expired, cb_data);
            return FIDO_ERROR_NONE;
        }
        else {
            _free_app_id_cb_data(cb_data);
            return FIDO_ERROR_PERMISSION_DENIED;
        }
    }

    const char *scheme = soup_uri_get_scheme(parsed_uri);
    if (scheme == NULL) {
         _free_app_id_cb_data(cb_data);
         return FIDO_ERROR_INVALID_PARAMETER;
    }

    if (strcmp(SOUP_URI_SCHEME_HTTPS, scheme) != 0) {
        _free_app_id_cb_data(cb_data);
        return FIDO_ERROR_INVALID_PARAMETER;
    }

    _INFO("%s", uaf_app_id);

    SoupMessage *soup_message = soup_message_new_from_uri ("GET", parsed_uri);

    soup_uri_free(parsed_uri);

    SoupSession *session = soup_session_new_with_options(
                SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_PROXY_RESOLVER_DEFAULT,
                SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, TRUE,
                SOUP_SESSION_TIMEOUT, _MAX_NW_TIME_OUT,
                NULL);

    bool ssl_strict = FALSE;//changed to make sure https cert errors dont occur, only for testing
    g_object_set(session, "ssl-strict", ssl_strict, NULL);

    soup_session_queue_message(session, soup_message, __soup_cb, cb_data);

    _INFO("Added in soup_session_queue_message");

    return FIDO_ERROR_NONE;
}
