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
#if !GLIB_CHECK_VERSION(2, 31, 0)
#include <glib/gmacros.h>
#endif

#include <json-glib/json-glib.h>
#include "fido_internal_types.h"
#include "fido_logs.h"

#include "dummy-asm-stub.h"

#define _DUMMY_ASM_SERVICE_DBUS_PATH       "/org/tizen/dummyasm"

#define _GET_INFO_RESPONSE "{\"responseData\":{\"Authenticators\":[{\"aaid\":\"0001#8001\",\"asmVersions\":[{\"major\":1,\"minor\":0}],\"assertionScheme\":\"UAFV1TLV\",\"title\":\"UAF PIN 1\",\"attestationTypes\":[15879],\"tcDisplayContentType\":\"text/plain\",\"description\":\"Pretty long description\",\"supportedExtensionIDs\":[\"abc\"],\"icon\":\"data:image/png;base64,iVBORw0KGgoAAA\",\"isRoamingAuthenticator\":false,\"isSecondFactorOnly\":false,\"isUserEnrolled\":true,\"keyProtection\":1,\"matcherProtection\":1,\"hasSettings\":true,\"tcDisplay\":1,\"authenticatorIndex\":1,\"authenticationAlgorithm\":1,\"attachmentHint\":1,\"userVerification\":4},{\"aaid\":\"DDDD#C001\",\"asmVersions\":[{\"major\":1,\"minor\":0}],\"assertionScheme\":\"UAFV1TLV\",\"title\":\"UAF PIN 2\",\"attestationTypes\":[15879],\"tcDisplayContentType\":\"text/plain\",\"description\":\"Pretty long description\",\"supportedExtensionIDs\":[\"abc\"],\"icon\":\"data:image/png;base64,iVBORw0KGgoAAA\",\"isRoamingAuthenticator\":false,\"isSecondFactorOnly\":false,\"isUserEnrolled\":true,\"keyProtection\":1,\"matcherProtection\":1,\"hasSettings\":true,\"tcDisplay\":1,\"authenticatorIndex\":2,\"authenticationAlgorithm\":1,\"attachmentHint\":1,\"userVerification\":4}]},\"statusCode\":0}"

#define _REG_RESPONSE "{\"responseData\":{\"assertion\":\"AT7gAgM-sQALLgkAMDAwMSM4MDAxDi4HAAABAQEAAAEKLiAAbuzkawu9cagRfQWDaOHkQAraLfwuBlCX5WEbQn-2vCQJLiAA1eVp7JIQlwm6YF0YEmGZdNCA27qZoIcZGC0Uaw71bR8NLggAAQAAAAEAAAAMLkEABDvrbVayiXwIsfShzUc2ALT8K3pZKykYGvpD7nU5Jy4sEXEKsepcRfZebCH7RHLwbchz6AmrK-3o1RAbauiuZMcHPicCBi5AAE3tsSOmUITLnQdbRTXdIe2R27E3e3JarZ8MT-9qcZug7__AM5ZUrXqyzSMhRCz9yHEhaeRMyRctxcD18uimqikFLt8BMIIB2zCCAYICCQDDAwxEtwee0TAJBgcqhkjOPQQBMHsxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTELMAkGA1UEBwwCUEExEDAOBgNVBAoMB05OTCxJbmMxDTALBgNVBAsMBERBTjExEzARBgNVBAMMCk5OTCxJbmMgQ0ExHDAaBgkqhkiG9w0BCQEWDW5ubEBnbWFpbC5jb20wHhcNMTQxMjE4MTYwMzEyWhcNMjQxMjE1MTYwMzEyWjByMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVBhbG8gQWx0bzEbMBkGA1UECgwSTm9rIE5vayBMYWJzLCBJbmMuMSUwIwYJKoZIhvcNAQkBFhZub2tub2tjZXJ0c0Bub2tub2suY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhNa9EIVUCSqfiALGZXM1Zc32gFJfTpGFHIQD5OciVVs4HAl9o1mQOA9WPKhAWH_2dEubn0fQSi1sq4EaOReesjAJBgcqhkjOPQQBA0gAMEUCIHeQm_CRb_joYNff0v9OIzt3FKHvlCZh6ErUldOqUW-UAiEA2kNe-dEqXki2ikfMq79SO7ernvtSZ8X99PuhmMVjxT0\",\"assertionScheme\":\"UAFV1TLV\"},\"statusCode\":0}"

#define _AUTH_RESPONSE "{\"responseData\":{\"assertion\":\"Aj7WAAQ-jgALLgkAMDAwMSM4MDAxDi4FAAABAQEADy4gAPyMxESI2aTWj7ETwRifnwh3EBOiZdCJDPeFTZuit-ivCi4gABsFkal_ID2-Q2jC0Mtblw4_ApXVeaogzzD-iE3erYUuEC4AAAkuIADV5WnskhCXCbpgXRgSYZl00IDbupmghxkYLRRrDvVtHw0uBAACAAAABi5AAGewExLjMHW0S6iVoHqGzGS8-qGmLfc35WdBSawTDx0rF7sbXUpQQ9LkK4LM-Fu3YgmpEEBXT254dIXbJzr4_oE\",\"assertionScheme\":\"UAFV1TLV\"},\"statusCode\":0}"

#define _DEREG_RESPONSE "{\"statusCode\" : 0}"

#define _GET_REGISTRATIONS_RESPONSE "{\"responseData\":{\"appRegs\":[{\"appID\":\"https://qa-egypt.noknoktest.com:443/UAFSampleProxy/uaf/facets.uaf\",\"keyIDs\":[\"1eVp7JIQlwm6YF0YEmGZdNCA27qZoIcZGC0Uaw71bR8\"]}]},\"statusCode\":0}"

#define _FREEDESKTOP_SERVICE    "org.freedesktop.DBus"
#define _FREEDESKTOP_PATH       "/org/freedesktop/DBus"
#define _FREEDESKTOP_INTERFACE  "org.freedesktop.DBus"

#define _FIDO_SERVICE_PATH "/usr/bin/fido-service"

static guint owner_id = 0;

static Dummyasm* __dbus_obj = NULL;

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

static char*
__get_request_type(const char *asm_req_json)
{
	if (asm_req_json == NULL)
		return NULL;

	JsonParser *parser = json_parser_new();
	RET_IF_FAIL(parser != NULL, NULL);

	GError *parse_err = NULL;
	json_parser_load_from_data(parser, asm_req_json, -1, &parse_err);
	RET_IF_FAIL(parse_err == NULL, NULL);

	JsonNode *root = json_parser_get_root(parser);
	RET_IF_FAIL(root != NULL, NULL);

	JsonObject *root_obj = json_node_get_object(root);

	const char *req_type = json_object_get_string_member(root_obj, "requestType");

	return strdup(req_type);

}

gboolean
_dbus_on_asm_request(Dummyasm *object, GDBusMethodInvocation *invocation, const gchar *uaf_request_json)
{
	_INFO("_dbus_on_asm_request");

	char *caller_path = __get_proc_path_of_dbus_caller(invocation);
	if (caller_path == NULL) {
		_ERR("Failed to get caller path");
		dummyasm_complete_asm_request(object, invocation, -1, NULL);
		return true;
	}

	if (strcmp(caller_path, _FIDO_SERVICE_PATH) != 0) {
		_ERR("Only fido-service is allowed to call ASM");
		dummyasm_complete_asm_request(object, invocation, -1, NULL);
		return true;
	}

	char *req_type = __get_request_type(uaf_request_json);
	if (req_type == NULL) {
		 dummyasm_complete_asm_request(object, invocation, -1, NULL);
		return true;
	}

	_INFO("request type=[%s]", req_type);

	if (strcmp(req_type, "GetInfo") == 0)
		dummyasm_complete_asm_request(object, invocation, 0, _GET_INFO_RESPONSE);
	if (strcmp(req_type, "Register") == 0)
		dummyasm_complete_asm_request(object, invocation, 0, _REG_RESPONSE);
	if (strcmp(req_type, "Authenticate") == 0)
		dummyasm_complete_asm_request(object, invocation, 0, _AUTH_RESPONSE);
	if (strcmp(req_type, "Deregister") == 0)
		dummyasm_complete_asm_request(object, invocation, 0, _DEREG_RESPONSE);
	if (strcmp(req_type, "GetRegistrations") == 0)
		dummyasm_complete_asm_request(object, invocation, 0, _GET_REGISTRATIONS_RESPONSE);

	return true;
}

static void
on_bus_acquired(GDBusConnection *connection, const gchar *name, gpointer user_data)
{
		_INFO("on_bus_acquired");

		GDBusInterfaceSkeleton* interface = NULL;
		__dbus_obj = dummyasm_skeleton_new();
		if (__dbus_obj == NULL)
			return;

		interface = G_DBUS_INTERFACE_SKELETON(__dbus_obj);
		if (!g_dbus_interface_skeleton_export(interface, connection, _DUMMY_ASM_SERVICE_DBUS_PATH, NULL))
			return;

		_INFO("before g_signal_connect");
		g_signal_connect(__dbus_obj, "handle_asm_request",
						G_CALLBACK(_dbus_on_asm_request), NULL);
}

static void
on_name_acquired(GDBusConnection *connection,
						const gchar     *name,
						gpointer         user_data)
{
	_INFO("on_name_acquired");
}

static void
on_name_lost(GDBusConnection *connection,
						const gchar     *name,
						gpointer         user_data)
{
	_INFO("on_name_lost");
	exit(1);
}

static bool _initialize_dbus()
{
	_INFO("_initialize_dbus");
	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
							 "org.tizen.dummyasm",
							 G_BUS_NAME_OWNER_FLAGS_NONE,
							 on_bus_acquired,
							 on_name_acquired,
							 on_name_lost,
							 NULL,
							 NULL);

	if (owner_id == 0) {
			_INFO("owner_id is 0");
			return false;
	}

	return true;
}

static void
_initialize(void)
{
#if !GLIB_CHECK_VERSION(2, 35, 0)
	g_type_init();
#endif

	if (_initialize_dbus() == false) {
		/* because dbus's initialize failed, we cannot continue any more. */
		exit(1);
	}
}

int
main(void)
{
	GMainLoop *mainloop = NULL;

	mainloop = g_main_loop_new(NULL, FALSE);

	_initialize();

	g_main_loop_run(mainloop);

	return 0;
}
