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
#include <app_manager.h>
#include <package_manager.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <pkgmgr-info.h>
#include <aul.h>

#include "fido_internal_types.h"
#include "fido_json_handler.h"
#include "fido_app_id_handler.h"
#include "fido_logs.h"

#define _FREEDESKTOP_SERVICE    "org.freedesktop.DBus"
#define _FREEDESKTOP_PATH       "/org/freedesktop/DBus"
#define _FREEDESKTOP_INTERFACE  "org.freedesktop.DBus"

#define _MAX_NW_TIME_OUT 20

#define FIDO_APP_ID_KEY_TIZEN "tizen"
#define FIDO_APP_ID_KEY_PKG_HASH "pkg-key-hash"

typedef struct _app_id_cb_data {
	char *caller_app_id;
	char *real_app_id;
	_facet_id_cb cb;
	void *user_data;
} _app_id_cb_data_t;

typedef struct _cert_match_info {
	const char *cert_str;
	bool is_matched;
} cert_match_info_s;

#ifdef WITH_JSON_BUILDER
static uid_t __get_uid_of_dbus_caller(GDBusMethodInvocation *invocation);
#endif

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

#ifdef WITH_JSON_BUILDER
static char*
__get_appid(GDBusMethodInvocation *invocation, pid_t pid)
{

	uid_t uid = __get_uid_of_dbus_caller(invocation);
	char *app_id = calloc(1024, sizeof(char));
	int ret = aul_app_get_appid_bypid_for_uid(pid, app_id, 1023, uid);
	if (ret != AUL_R_OK) {
		_ERR("aul_app_get_appid_bypid_for_uid failed [%d]", ret);
		free(app_id);

		return NULL;
	}

	return app_id;
}
#else
static char*
__get_appid(GDBusMethodInvocation *invocation, pid_t remote_pid)
{
	char *app_id = NULL;
	int ret = app_manager_get_app_id(remote_pid, &app_id);

	if (app_id == NULL) {
		_ERR("app_manager_get_app_id for %d failed = %d", remote_pid, ret);

		/* Exception case : Daemons will not have app-ids, for them path will be set : /usr/bin/sample-service */
		char buf[128];
		int ret = 0;

		snprintf(buf, sizeof(buf), "/proc/%d/cmdline", remote_pid);
		ret = __read_proc(buf, buf, sizeof(buf));
		if (ret <= 0) {
			_ERR("No proc directory (%d)\n", remote_pid);
			return NULL;
		}

		_INFO("Caller=[%s]", buf);

		app_id = strdup(buf);
	}


	return app_id;
}
#endif


static char*
__get_appid_of_dbus_caller(GDBusMethodInvocation *invocation)
{
	pid_t remote_pid = 0;
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
		_ERR("Failed to open connection for the invocation");
		return NULL;
	}

	error = NULL;
	response = g_dbus_connection_call_sync(connection,
				_FREEDESKTOP_SERVICE, _FREEDESKTOP_PATH,
				_FREEDESKTOP_INTERFACE, "GetConnectionUnixProcessID",
				g_variant_new("(s)", sender), ((const GVariantType *) "(u)"),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	//g_object_unref (connection);

	if (response == NULL) {
		_ERR("Failed to get caller id [%s]", error->message);
		g_error_free(error);
		return NULL;
	}

	g_variant_get(response, "(u)", &upid);
	_INFO("Remote msg-bus peer service=%s pid=%u", sender, upid);
	remote_pid = (pid_t) upid;

	g_variant_unref(response);

	return __get_appid(invocation, remote_pid);
}

#ifdef WITH_JSON_BUILDER
static uid_t
__get_uid_of_dbus_caller(GDBusMethodInvocation *invocation)
{
	GError *error = NULL;
	GDBusConnection *connection = NULL;
	const gchar *sender = NULL;

	sender = g_dbus_method_invocation_get_sender(invocation);
	if (!sender) {
		_ERR("Failed to get sender");
		return 0;
	}

	connection = g_dbus_method_invocation_get_connection(invocation);
	if (connection == NULL) {
		_ERR("Failed to open connection for the invocation");
		return 0;
	}

	GVariant *result = g_dbus_connection_call_sync(connection,
		"org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
		"GetConnectionUnixUser", g_variant_new("(s)", sender), G_VARIANT_TYPE("(u)"),
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (result != NULL) {
		uid_t uid;
		g_variant_get(result, "(u)", &uid);
		g_variant_unref(result);

		return uid;
	}

	return 0;
}
#endif

/*tizen:pkg-key-hash:<sha256_hash-of-public-key-of-pkg-author-cert>*/
const char*
__get_pub_key(const char *json_id_str)
{
	_INFO("__get_pub_key starting");

	RET_IF_FAIL(json_id_str != NULL, NULL);


	char *save_ptr;
	char *os = strtok_r(strdup(json_id_str), ":", &save_ptr);

	RET_IF_FAIL(os != NULL, NULL);

	if (strcmp(os, FIDO_APP_ID_KEY_TIZEN) != 0) {
		_ERR("[%s] is not supported", os);
		return NULL;
	}

	char *type = strtok_r(NULL, ":", &save_ptr);
	RET_IF_FAIL(type != NULL, NULL);

	if (strcmp(type, FIDO_APP_ID_KEY_PKG_HASH) != 0) {
		_ERR("[%s] is not supported", type);
		return NULL;
	}

	char *pub_key = strtok_r(NULL, ":", &save_ptr);
	RET_IF_FAIL(pub_key != NULL, NULL);

	_INFO("__get_pub_key end");

	return pub_key;
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
		_INFO("%s", id);
		/*Rule = tizen:pkg-key-hash:<sha256_hash-of-public-key-of-pkg-author-cert>*/
		if (strcmp(cb_data->caller_app_id, id) == 0) {
			real_app_id = strdup(id);
			error_code = FIDO_ERROR_NONE;

			_INFO("Match found");
			break;
		}
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

static char*
__b64_url_encode(unsigned char *input, int ip_len)
{
	int i = 0;
	unsigned char *output = calloc(ip_len * 1.5, sizeof(char));
	int outlen = 0;

	BIO * bmem = NULL;
	BIO * b64 = NULL;
	BUF_MEM * bptr = NULL;
	b64 = BIO_new(BIO_f_base64());
	if(b64 == NULL) {
		_ERR("BIO_new failed \n");
		free(output);
		return NULL;
	}
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, ip_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	memcpy(output, bptr->data, bptr->length);
	output[bptr->length] = 0;
	outlen = bptr->length;
	if(b64)
		BIO_free_all(b64);

	for(; i < outlen ; i++) {
		if(output[i] == '+') {
			output[i] = '-';
		} else if(output[i] == '/') {
			output[i] = '_';
		} else if(output[i] == '=') {
			outlen = i ;
			output[i] = '\0';
			break;
		}
	}

	return (char*)output;
}

static char*
__get_digest_b64(const char *message)
{
	RET_IF_FAIL(message != NULL, NULL);

	unsigned char *digest = NULL;
	int message_len = strlen(message);
	unsigned int digest_len = 0;

	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		return NULL;

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		return NULL;

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		return NULL;

	if((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		return NULL;

	if(1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len))
		return NULL;

	EVP_MD_CTX_destroy(mdctx);

	return __b64_url_encode(digest, (int)digest_len);
}

/*3.0*/
#ifdef WITH_JSON_BUILDER
/*tizen:pkg-key-hash:<sha256_hash-of-public-key-of-pkg-author-cert>*/
static char*
__get_tz_facet_id_of_caller(const char *caller_app_id, GDBusMethodInvocation *invocation)
{
	RET_IF_FAIL(caller_app_id != NULL, NULL);

	uid_t uid = __get_uid_of_dbus_caller(invocation);
	_INFO("Caller uid =[%d]", uid);

	pkgmgrinfo_pkginfo_h handle = NULL;
	int ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(caller_app_id, uid, &handle);
	if (ret < 0) {
		_ERR("pkgmgrinfo_pkginfo_get_usr_pkginfo failed [%d]", ret);
		return NULL;
	}

	_INFO("");

	char *pkgid = NULL;
	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret != PMINFO_R_OK) {

		_ERR("pkgmgrinfo_pkginfo_get_pkgid failed [%d]", ret);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return NULL;
	}

	_INFO("");

	pkgmgrinfo_certinfo_h cert_handle;
	const char *author_cert = NULL;
	ret = pkgmgrinfo_pkginfo_create_certinfo(&cert_handle);
	if (ret != PMINFO_R_OK) {
		_ERR("");
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return NULL;
	}

	_INFO("");

	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, cert_handle, uid);
	if (ret != PMINFO_R_OK) {
		_ERR("");
		pkgmgrinfo_pkginfo_destroy_certinfo(cert_handle);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return NULL;
	}

	_INFO("");

	ret = pkgmgrinfo_pkginfo_get_cert_value(cert_handle, PMINFO_AUTHOR_SIGNER_CERT, &author_cert);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_destroy_certinfo(cert_handle);
		_ERR("");
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return NULL;
	}

	_INFO("");

	pkgmgrinfo_pkginfo_destroy_certinfo(cert_handle);

	_INFO("");

	char *author_cert_hash = NULL;
	char *tz_facet_id = NULL;
	int tz_facet_id_max_len = -1;


	tz_facet_id_max_len = strlen(author_cert) + 128;
	tz_facet_id = (char*)(calloc(1, tz_facet_id_max_len));
	author_cert_hash = __get_digest_b64(author_cert);
	_INFO("");
	CATCH_IF_FAIL(author_cert_hash != NULL);

	snprintf(tz_facet_id, tz_facet_id_max_len, "%s:%s", "tizen:pkg-key-hash",
			 author_cert_hash);
	_INFO("");


CATCH :

	_INFO("Before return");

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	_INFO("");
	return tz_facet_id;
}
#else
/*<= 2.4*/
static bool
__author_cert_cb(package_info_h handle, package_cert_type_e cert_type,
				 const char *cert_value, void *user_data)
{

	if ((cert_type ==  PACKAGE_INFO_AUTHOR_SIGNER_CERT) &&
			(cert_value != NULL) && (user_data != NULL)) {

		char *author_cert = strdup(cert_value);

		char **author_cert_op = (char **)user_data;
		*author_cert_op = author_cert;

		return false;
	}

	return true;
}

static char*
__get_tz_facet_id_of_caller(const char *caller_app_id, GDBusMethodInvocation *invocation)
{
	RET_IF_FAIL(caller_app_id != NULL, NULL);

	app_info_h app_info = NULL;
	int ret = app_info_create(caller_app_id, &app_info);
	if (ret != APP_MANAGER_ERROR_NONE) {
		_ERR("app_info_create failed [%d]", ret);
		return NULL;
	}

	package_info_h pkg_info = NULL;
	char *pkg_name = NULL;

	char *author_cert = NULL;
	char *author_cert_hash = NULL;
	char *tz_facet_id = NULL;
	int tz_facet_id_max_len = -1;

	_INFO("Before app_info_get_package");

	ret = app_info_get_package(app_info, &pkg_name);
	CATCH_IF_FAIL(ret == APP_MANAGER_ERROR_NONE);

	_INFO("Before package_info_create [%s]", pkg_name);
	ret = package_info_create(pkg_name, &pkg_info);
	CATCH_IF_FAIL(ret == APP_MANAGER_ERROR_NONE);

	_INFO("Before package_info_foreach_cert_info");
	package_info_foreach_cert_info(pkg_info, __author_cert_cb, &author_cert);

	_INFO("After foreach_cert_info");

	CATCH_IF_FAIL(author_cert != NULL);

	tz_facet_id_max_len = strlen(author_cert) + 128;
	tz_facet_id = (char*)(calloc(1, tz_facet_id_max_len));
	author_cert_hash = __get_digest_b64(author_cert);
	CATCH_IF_FAIL(author_cert_hash != NULL);

	snprintf(tz_facet_id, tz_facet_id_max_len, "%s:%s", "tizen:pkg-key-hash",
			 author_cert_hash);


CATCH :
	app_info_destroy(app_info);
	_INFO("After app_info_destroy");

	package_info_destroy(pkg_info);
	_INFO("After package_info_destroy");

	SAFE_DELETE(pkg_name);

	_INFO("Before return");

	return tz_facet_id;
}
#endif


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

	/* Tizen Facet Id is:
	*  "tizen:pkg-key-hash:B64UrlEncode(Sha256Digest(<pkg-author-cert>))"
	*/
	cb_data->caller_app_id = __get_tz_facet_id_of_caller(app_id, invocation);
	if (cb_data->caller_app_id == NULL) {
		SAFE_DELETE(cb_data);
		return FIDO_ERROR_PERMISSION_DENIED;
	}
	_INFO("Caller's Facet Id=%s", cb_data->caller_app_id);

	cb_data->cb = cb;
	cb_data->user_data = user_data;

	/*Case 1: UAF JSON does not have appID, so no check is required, put facetid*/
	if (uaf_app_id == NULL) {
		_INFO("UAF msg does not have appID");
		cb_data->real_app_id = __get_tz_facet_id_of_caller(app_id, invocation);
		g_timeout_add(2, __timer_expired, cb_data);
		return FIDO_ERROR_NONE;
	}


	SoupURI *parsed_uri = soup_uri_new(uaf_app_id);

	/*Case 2: UAF JSON is not URL, so string comparison check is required*/
	if (parsed_uri == NULL) {

		_INFO("UAF msg has direct appID");

		if (strcmp(cb_data->caller_app_id, uaf_app_id) == 0) {
			cb_data->real_app_id = strdup(uaf_app_id);
			g_timeout_add(2, __timer_expired, cb_data);
			return FIDO_ERROR_NONE;
		} else {
			_free_app_id_cb_data(cb_data);
			return FIDO_ERROR_PERMISSION_DENIED;
		}
	}

	_INFO("UAF msg has appID url");
	/* Case 3: UAF JSON is URL, so fetch the json from this url, then look for
	* tizen:pkg-key-hash in "ids" array, allow only if its matched with the caller's value.
	*/
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

	SoupMessage *soup_message = soup_message_new_from_uri("GET", parsed_uri);

	soup_uri_free(parsed_uri);

#ifdef WITH_JSON_HANDLER
	SoupSession *session = soup_session_new_with_options(
							SOUP_SESSION_ADD_FEATURE_BY_TYPE,
							SOUP_TYPE_PROXY_RESOLVER_DEFAULT,
							SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, TRUE,
							SOUP_SESSION_TIMEOUT, _MAX_NW_TIME_OUT,
							NULL);
#else
	SoupSession *session = soup_session_async_new_with_options(
							SOUP_SESSION_ADD_FEATURE_BY_TYPE,
							SOUP_TYPE_PROXY_RESOLVER_DEFAULT,
							SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, TRUE,
							SOUP_SESSION_TIMEOUT, _MAX_NW_TIME_OUT,
							NULL);
#endif

	bool ssl_strict = FALSE;//changed to make sure https cert errors dont occur, only for testing
	g_object_set(session, "ssl-strict", ssl_strict, NULL);

	soup_session_queue_message(session, soup_message, __soup_cb, cb_data);

	_INFO("Added in soup_session_queue_message");

	return FIDO_ERROR_NONE;
}
