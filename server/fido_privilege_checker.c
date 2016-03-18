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

#include "fido_privilege_checker.h"
#include "fido_logs.h"

#ifdef USE_JSON_BUILDER
#include <cynara-client.h>
#include <cynara-session.h>
#include <cynara-creds-gdbus.h>
static cynara *__cynara = NULL;
#endif

#define _DISABLE_PRIV_CHECK

static guint
_get_client_pid(GDBusMethodInvocation* invoc)
{
	const char *name = NULL;
	name = g_dbus_method_invocation_get_sender(invoc);
	if (name == NULL)
	{
		_ERR("g_dbus_method_invocation_get_sender failed");
		return -1;
	}
	_INFO("sender=[%s]", name);


	guint pid = -1;
	GError *error = NULL;
	GVariant *_ret;

	_INFO("calling GetConnectionUnixProcessID");

	GDBusConnection* conn = g_dbus_method_invocation_get_connection(invoc);
	_ret = g_dbus_connection_call_sync(conn,
			"org.freedesktop.DBus",
			"/org/freedesktop/DBus",
			"org.freedesktop.DBus",
			"GetConnectionUnixProcessID",
			g_variant_new("(s)", name),
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (_ret != NULL) {
		g_variant_get(_ret, "(u)", &pid);
		g_variant_unref(_ret);
	}

	_INFO("process Id = [%u]", pid);
	return pid;
}

static int
__check_privilege_by_cynara(const char *client, const char *session, const char *user, const char *privilege)
{
	#ifdef USE_JSON_BUILDER
	
	int ret;
	char err_buf[128] = {0,};

	ret = cynara_check(__cynara, client, session, user, privilege);
	switch (ret) {
		case CYNARA_API_ACCESS_ALLOWED:
			_DBG("cynara_check success");
			return FIDO_ERROR_NONE;

		case CYNARA_API_ACCESS_DENIED:
			_ERR("cynara_check permission deined, privilege=%s, error = CYNARA_API_ACCESS_DENIED", privilege);
			return FIDO_ERROR_PERMISSION_DENIED;

		default:
			cynara_strerror(ret, err_buf, sizeof(err_buf));
			_ERR("cynara_check error : %s, privilege=%s, ret = %d", err_buf, privilege, ret);
			return FIDO_ERROR_PERMISSION_DENIED;
	}
	
	return FIDO_ERROR_NONE;
	#endif
	
	return FIDO_ERROR_NONE;
}

static int
__get_information_for_cynara_check(GDBusMethodInvocation *invocation, char **client, char **user, char **session)
{
	#ifdef USE_JSON_BUILDER
	
	GDBusConnection *gdbus_conn = NULL;
	char* sender = NULL;
	int ret = -1;

	gdbus_conn = g_dbus_method_invocation_get_connection(invocation);
	if(gdbus_conn == NULL) {
		_ERR("g_dbus_method_invocation_get_connection failed");
		return -1;
	}

	sender = (char*) g_dbus_method_invocation_get_sender(invocation);
	if (sender == NULL) {
		_ERR("g_dbus_method_invocation_get_sender failed");
		return -1;
	}

	ret = cynara_creds_gdbus_get_user(gdbus_conn, sender, USER_METHOD_DEFAULT, user);
	if (ret != CYNARA_API_SUCCESS) {
		_ERR("cynara_creds_gdbus_get_user failed, ret = %d", ret);
		return -1;
	}

	ret = cynara_creds_gdbus_get_client(gdbus_conn, sender, CLIENT_METHOD_DEFAULT, client);
	if (ret != CYNARA_API_SUCCESS) {
		_ERR("cynara_creds_gdbus_get_client failed, ret = %d", ret);
		return -1;
	}

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	*session = cynara_session_from_pid(pid);
	if (*session == NULL) {
		_ERR("cynara_session_from_pid failed");
		return -1;
	}
	return FIDO_ERROR_NONE;
	#endif
	
	return FIDO_ERROR_NONE;
}

bool
is_allowed_to_call(GDBusMethodInvocation *invocation, const char* privilege)
{
	#ifdef USE_JSON_BUILDER
	
	int ret = -1;

	if (__cynara == NULL) {
		ret = cynara_initialize(&__cynara, NULL);
		if(ret != CYNARA_API_SUCCESS) {
			_ERR("CYNARA Initialization fail");
			return false;
		}
	}

	char *client = NULL;
	char *session = NULL;
	char *user = NULL;

	ret = __get_information_for_cynara_check(invocation, &client, &user, &session);
	if ( ret != FIDO_ERROR_NONE) {
		_ERR("__get_information_for_cynara_check failed");
		g_free(client);
		g_free(user);
		SAFE_DELETE(session);

		return false;
	}

	ret = __check_privilege_by_cynara(client, session, user, privilege);

	/*TODO enable after smack is defined*/
#ifndef _DISABLE_PRIV_CHECK
	if ( ret != FIDO_ERROR_NONE) {
		_ERR("__check_privilege_by_cynara failed, ret = %d", ret);
		g_free(client);
		g_free(user);
		SAFE_DELETE(session);

		return false;
	}
#endif
	g_free(client);
	g_free(user);
	SAFE_DELETE(session);

	return true;
	#endif
	
	return true;
}
