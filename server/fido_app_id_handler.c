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
#include <openssl/x509.h>
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


static char*
__get_appid(GDBusMethodInvocation *invocation, pid_t pid)
{
	char *app_id = calloc(1024, sizeof(char));

#ifdef WITH_JSON_BUILDER
	uid_t uid = __get_uid_of_dbus_caller(invocation);
	int ret = aul_app_get_appid_bypid_for_uid(pid, app_id, 1023, uid);
#else
	int ret = aul_app_get_appid_bypid(pid, app_id, 1023);
#endif

	if (ret != AUL_R_OK) {
		_ERR("AUL Get App ID failed [%d]", ret);
		free(app_id);

		return NULL;
	}

	return app_id;
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

/*"tizen:pkg-key-hash:B64Encode(Sha256Digest(<Author Root Cert Public Key>))"*/
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
__b64_encode(unsigned char *input, int ip_len)
{
	RET_IF_FAIL(input != NULL, NULL);
	RET_IF_FAIL(ip_len > 0, NULL);

	unsigned char *output = calloc(ip_len * 1.5, sizeof(char));

	BIO *bmem = NULL;
	BIO *b64 = NULL;
	BUF_MEM *bptr = NULL;
	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
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

	if (b64)
		BIO_free_all(b64);

	return (char*)output;
}

static int
__b64_decode(const char *encoded_data, int encoded_size, unsigned char **decoded_data, int *decoded_size)
{
	RET_IF_FAIL(encoded_data != NULL, -1);

	//_INFO("%s", encoded_data);

	int len = 0;
	*decoded_size = encoded_size;

	(*decoded_data) = (unsigned char *) calloc((*decoded_size) * 1.5, sizeof(char));

	BIO *bmem = BIO_new_mem_buf((void *) encoded_data, (*decoded_size));

	BIO *bioCmd = BIO_new(BIO_f_base64());

	BIO_set_flags(bioCmd, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_push(bioCmd, bmem);

	len = BIO_read(bmem, (void *) (*decoded_data), (*decoded_size));
	_INFO("%d", len);

	*decoded_size = len;

	BIO_free_all(bmem);

	_INFO("");

	return 0;
}

static char*
__get_pub_key_from_cert(const char *cert_b64)
{
	RET_IF_FAIL(cert_b64 != NULL, NULL);

	unsigned char pubkey_der_digest[SHA256_DIGEST_LENGTH] = {0, };

	unsigned char* cert_raw = NULL;//calloc(strlen(cert_b64) * 1.5, sizeof(char));

	int cert_raw_len = 0;

	int ret = __b64_decode(cert_b64, strlen(cert_b64), &cert_raw, &cert_raw_len);
	if (ret != 0) {
		_ERR("__b64_decode failed");
		free(cert_raw);

		return NULL;
	}

	X509 *x509 = d2i_X509(NULL, (const unsigned char **)(&cert_raw), cert_raw_len);
	if (x509 == NULL) {
		_ERR("d2i_X509 failed");
		free(cert_raw);
		return NULL;
	}

	int der_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509), NULL);
	if (der_len <= 0) {
		_ERR("i2d_X509_PUBKEY failed");
		free(cert_raw);
		return NULL;
	}

	unsigned char* der_pubkey  = NULL;

	unsigned char* der_pubkey_temp = NULL;

	int hashed_len = 0;

	der_pubkey_temp = der_pubkey = (unsigned char*)OPENSSL_malloc(der_len);

	i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509), (unsigned char **)&der_pubkey_temp);

	ret = EVP_Digest(der_pubkey, der_len, pubkey_der_digest, (unsigned int*)&hashed_len, EVP_sha256(), NULL);

	if (ret != 1) {
		_ERR("EVP_Digest failed");
		OPENSSL_free(der_pubkey);

		return NULL;
	}

	char *pub_key =  __b64_encode(pubkey_der_digest, (int)hashed_len);

	OPENSSL_free(der_pubkey);

	return pub_key;
}

/*tizen:pkg-key-hash:<sha256_hash-of-public-key-of-pkg-author-cert>*/
static char*
__get_tz_facet_id_of_caller(const char *caller_app_id, GDBusMethodInvocation *invocation)
{
	RET_IF_FAIL(caller_app_id != NULL, NULL);

#ifdef WITH_JSON_BUILDER
	uid_t uid = __get_uid_of_dbus_caller(invocation);
	_INFO("Caller uid =[%d]", uid);
#endif

	pkgmgrinfo_pkginfo_h handle = NULL;

#ifdef WITH_JSON_BUILDER
	int ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(caller_app_id, uid, &handle);
#else
	int ret = pkgmgrinfo_pkginfo_get_pkginfo(caller_app_id, &handle);
#endif

	if (ret < 0) {
		_ERR("Get Pkg Info Failed failed [%d]", ret);
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

#ifdef WITH_JSON_BUILDER
	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, cert_handle, uid);
#else
	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, cert_handle);
#endif

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

	/*_INFO("Author Root Cert=%s", author_cert);*/

	_INFO("");

	char *author_cert_hash = NULL;
	char *tz_facet_id = NULL;
	int tz_facet_id_max_len = -1;


	author_cert_hash = __get_pub_key_from_cert(author_cert);
	_INFO("");
	CATCH_IF_FAIL(author_cert_hash != NULL);

	tz_facet_id_max_len = strlen(author_cert_hash) + 128;
	tz_facet_id = (char*)(calloc(1, tz_facet_id_max_len));
	snprintf(tz_facet_id, tz_facet_id_max_len, "%s:%s", "tizen:pkg-key-hash",
			 author_cert_hash);
	_INFO("");


CATCH:
	_INFO("Before return");

	pkgmgrinfo_pkginfo_destroy_certinfo(cert_handle);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	_INFO("");
	return tz_facet_id;
}

int
_verify_and_get_facet_id(const char *uaf_app_id, GDBusMethodInvocation *invocation, _facet_id_cb cb, void *user_data)
{
	_INFO("_verify_and_get_facet_id");

	char *app_id = __get_appid_of_dbus_caller(invocation);
	if (app_id == NULL)
		return FIDO_ERROR_PERMISSION_DENIED;

	_app_id_cb_data_t *cb_data = (_app_id_cb_data_t*)calloc(1, sizeof(_app_id_cb_data_t));
	if (cb_data == NULL)
		return FIDO_ERROR_OUT_OF_MEMORY;

	/* Tizen Facet Id is:
	*  "tizen:pkg-key-hash:B64Encode(Sha256Digest(<Author Root Cert Public Key>))"
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

	/*Case 2: Try assuming UAF JSON is not URL, so string comparison check is required*/
	if (strcmp(cb_data->caller_app_id, uaf_app_id) == 0) {
		_INFO("UAF msg has direct appID");

		cb_data->real_app_id = strdup(uaf_app_id);
		g_timeout_add(2, __timer_expired, cb_data);

		return FIDO_ERROR_NONE;
	}

	SoupURI *parsed_uri = soup_uri_new(uaf_app_id);
	if (parsed_uri == NULL) {

		_INFO("soup_uri_new failed");
		_free_app_id_cb_data(cb_data);
		return FIDO_ERROR_PERMISSION_DENIED;
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
