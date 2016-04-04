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

#ifndef FIDO_INTERNAL_TYPES_H
#define FIDO_INTERNAL_TYPES_H

#include <tizen.h>
#include <glib.h>
#include <stdlib.h>
#include <stdint.h>
#include <gio/gio.h>
#include "fido_uaf_types.h"

#define RET_IF_FAIL_VOID(cond) do {\
        if (!(cond)) {\
            return;\
        } \
} while (0)

#define RET_IF_FAIL(cond, err) do {\
        if (!(cond)) {\
            return err;\
        } \
} while (0)

#define CATCH_IF_FAIL(cond) do {\
        if (!(cond)) {\
            goto CATCH;\
        } \
} while (0)

#define CATCH_IF_FAIL_X(cond, expr) do {\
        if (!(cond)) {\
            expr;\
            goto CATCH;\
        } \
} while (0)

#define GOTO_IF_FAIL(cond, catch_block) do {\
        if (!(cond)) {\
            goto catch_block;\
        } \
} while (0)

#define SAFE_DELETE(x) do {\
    if (x != NULL) {\
        free(x);    \
        x = NULL;\
    } \
} while (0)

#define _SAFE_DUP(x) ((x) ? strdup(x) : NULL)

/* UAF API structures start */
/**
 *  @brief    UAF version structure.
 *  @since_tizen 3.0
 */
typedef struct _fido_version_s {
    int major;/** Major version **/
    int minor;/** Minor version **/
} fido_version_s;

typedef struct _fido_rgb_pallette_entry_s {
    unsigned short r;/** Red component**/
    unsigned short g;/** Green component**/
    unsigned short b;/** Blue component**/
} fido_rgb_pallette_entry_s;

typedef struct  _fido_display_png_characteristics_descriptor_s {
    unsigned long width;/** Width**/
    unsigned long height;/** Height**/
    uint8_t	bit_depth;/** Bit depth**/
    uint8_t color_type;/** Color type**/
    uint8_t compression;/** Compression**/
    uint8_t filter;/** Filter**/
    uint8_t interlace;/** Interlace**/
    GList *plte;/** Pallete entry list of type @c List of @c fido_rgb_pallette_entry_t elements **/
} fido_display_png_characteristics_descriptor_s;

void _free_display_png_characteristics_descriptor(fido_display_png_characteristics_descriptor_s *data);


/* UAF API structures end */


typedef struct _version {
    int major;
    int minor;
} _version_t;

typedef struct _extension {
    char *id;
    char *data;
    bool fail_if_unknown;
} _extension_t;

void _free_extension(_extension_t *data);

typedef struct _match_criteria {
    GList *aaid_list;
    GList *vendor_list;
    GList *key_id_list;
    long long int user_verification;
    int key_protection;
    int matcher_protection;
    long long int attachement_hint;
    int tc_display;
    GList *auth_algo_list;
    GList *assertion_scheme_list;
    GList *attestation_type_list;
    int auth_version;
    GList *extension_list;

} _match_criteria_t;

void _free_match_criteria(_match_criteria_t *data);

typedef struct _policy {
    GList *accepted_list;//2d array
    GList *disallowed_list;
    bool is_keyid_present; /*Only call GetRegistrations ASM call if atleast one match criteria contains keyIDs*/
} _policy_t;

void _free_policy(_policy_t *data);

typedef struct _op_header {
    _version_t *version;
    char *operation;
    char *app_id;
    char *server_data;
    GList *ext_list;
} _op_header_t;

void _free_op_header(_op_header_t *data);

typedef enum {
    _MESSAGE_TYPE_MIN = -1,
    _MESSAGE_TYPE_REG,
    _MESSAGE_TYPE_AUTH,
    _MESSAGE_TYPE_DEREG,
    _MESSAGE_TYPE_MAX
} _message_type_e;

typedef struct _message {
    char *facet_id;
    _op_header_t *header;
    char *channel_binding;
    _message_type_e type;
    void *data;/* type can be _reg_request_t / _auth_request_t / _dereg_request_t depending on header->operation */
} _message_t;

void _free_message(_message_t *data);

typedef struct _reg_request {
	char *challenge;
	char *user_name;
	_policy_t *policy;
	GList *png_list;/*ASM does not send it in reg resp, but client needs to send it back for reg resp*/
} _reg_request_t;

void _free_reg_request(_reg_request_t *data);

typedef struct _auth_transaction {
    char *content_type;
    char *content;
    fido_display_png_characteristics_descriptor_s *display_charac;
} _auth_transaction_t;

void _free_auth_transaction(_auth_transaction_t *data);

typedef struct _auth_request {
    char *challenge;
    GList *transaction_list;
    _policy_t *policy;
} _auth_request_t;

void _free_auth_request(_auth_request_t *data);

typedef struct _dereg_auth_info {
    char *aaid;
    char *key_id;
} _dereg_auth_info_t;

void _free_dereg_auth_info(_dereg_auth_info_t *data);

typedef struct _dereg_request {
    GList *auth_info_list;
} _dereg_request_t;

void _free_dereg_request(_dereg_request_t *data);

typedef struct _fido_asm_version {
    int major;
    int minor;
} _fido_asm_version_t;


typedef struct _fido_asm_rgb_pallette_entry {
    unsigned short r;
    unsigned short g;
    unsigned short b;
} _fido_asm_rgb_pallette_entry_t;


typedef struct  _fido_asm_display_png_characteristics_descriptor {
    unsigned long width;
    unsigned long height;
    int	bit_depth;
    int color_type;
    int compression;
    int filter;
    int interlace;
    GList *plte;
} _fido_asm_display_png_characteristics_descriptor_t;

void _free_asm_display_png_characteristics_descriptor_t(_fido_asm_display_png_characteristics_descriptor_t *data);

typedef struct _fido_asm_proxy {
    char *asm_id;
    char *vendor;
    char *bin_path;
    char *dbus_info;
    char *dbus_obj_path;
    char *dbus_interface_name;
    char *dbus_method_name;
    GDBusProxy *dbus_proxy;
} _fido_asm_proxy_t;

void _free_fido_asm_proxy(void *data);

typedef struct _asm_discover_response {
	int error_code;
    char *asm_id;
	char *asm_response_json;
} _asm_discover_response_t;

void _free_asm_discover_response(_asm_discover_response_t *data);

typedef struct _fido_asm_authenticator {
    GList *supported_versions;
    char *asm_id;
    char *auth_index;
    GList *key_ids;//filled up from GetRegistrations request to ASM
    GList *asm_versions;
    bool is_user_enrolled;
    bool has_settings;
    char *aaid;
    char *assertion_scheme;
    int authentication_algorithm;
    GList *attestation_types;
    unsigned long user_verification;
    int key_protection;
    int matcher_protection;
    unsigned long attachment_hint;
    bool is_second_factor_only;
    bool is_roaming;
    GList *supported_extension_IDs;
    int tc_display;
    char *tc_display_content_type;
    GList *tc_display_png_characteristics;
    char *title;
    char *description;
    char *icon;
} fido_authenticator_s;

void _free_fido_asm_authenticator(fido_authenticator_s *data);
void _free_fido_asm_authenticator_list_item(gpointer data);

typedef struct _fido_asm_reg_in {
    char *app_id;
    char *user_name;
    char *final_challenge;
    int attestation_type;
} _fido_asm_reg_in_t;

void _free_fido_asm_reg_in(_fido_asm_reg_in_t *data);

typedef struct _fido_asm_transaction {
    char *content_type;
    char *content;
    _fido_asm_display_png_characteristics_descriptor_t *display_charac;
} _fido_asm_transaction_t;

void _free_fido_asm_transaction(_fido_asm_transaction_t *data);

typedef struct _fido_asm_auth_in {
    char *app_id;
    GList *key_ids;
    char *final_challenge;
    GList *trans_list;//_fido_asm_transaction_t list
} _fido_asm_auth_in_t;

void _free_fido_asm_auth_in(_fido_asm_auth_in_t *data);

typedef struct _fido_asm_dereg_in {
    char *app_id;
    char *key_id;
} _fido_asm_dereg_in_t;

void _free_fido_asm_dereg_in(_fido_asm_dereg_in_t *data);

/* client sends list of this type to ui adaptor*/
typedef struct _ui_auth_data {
    char *asm_id;
    char *auth_index;
    char *label;
    int att_type;
} _ui_auth_data_t;

void _free_ui_auth_data(_ui_auth_data_t *data);

typedef struct _auth_reg_assertion {
	char *assertion_schm;
	char *assertion;
	GList *tc_disp_char_list;/*fido_display_png_characteristics_descriptor_s list*/
    //GList *ext_list;
} _auth_reg_assertion_t;

void _free_auth_reg_assertion(_auth_reg_assertion_t *data);
void _free_auth_reg_assertion_list_item(gpointer data);

typedef enum {
    _ASM_OUT_TYPE_MIN = -1,
    _ASM_OUT_TYPE_REG,
    _ASM_OUT_TYPE_AUTH,
    _ASM_OUT_TYPE_MAX
} _asm_out_type_e;

typedef struct _asm_out {
    int status_code;
    _asm_out_type_e type;
    void *response_data;/*type can be : _asm_reg_out_t, _asm_auth_out_t*/
    GList *ext_list;
} _asm_out_t;

void _free_asm_out(_asm_out_t *data);

typedef struct _asm_reg_out {
    char *assertion;
    char *assertion_schm;
} _asm_reg_out_t;

void _free_asm_reg_out(_asm_reg_out_t *data);

typedef struct _asm_auth_out {
    char *assertion;
    char *assertion_scheme;
} _asm_auth_out_t;

void _free_asm_auth_out(_asm_auth_out_t *data);

typedef struct _matched_auth_data {
    char *asm_id;
    char *auth_index;
    int att_type;
    char *label;
    GList *key_ids;
	GList *tc_display_png_characteristics;
} _matched_auth_data_t;

void _free_matched_auth_data(gpointer data);

typedef struct _matched_auth_dereg {
    char *asm_id;
    char *auth_index;
    char *app_id;
    char *key_id;
} _matched_auth_dereg_t;

void _free_matched_auth_dereg(_matched_auth_dereg_t *data);

typedef struct _asm_dereg_out {
    int status_code; /* 0 signifies success.*/
} _asm_dereg_out_t;

typedef struct _asm_app_reg {
    char *app_id;
    GList *key_id_list;
} _asm_app_reg_t;

void _free_asm_app_reg(_asm_app_reg_t *data);

typedef struct _asm_get_reg_out {
    int status_code;
    GList *app_reg_list;/*_asm_app_reg_t list*/
} _asm_get_reg_out_t;

void _free_asm_get_reg_out(_asm_get_reg_out_t *data);

typedef struct _dereg_q {
    GQueue *dereg_asm_in_q;
    void *cb_data;
} _dereg_q_t;

typedef void (*_fido_discover_asm_cb) (int tz_error_code, int fido_error_code, GList *asm_auth_info_list, void *user_data);

typedef struct __attribute__((packed)) _tlv {
    uint16_t type;
    uint16_t len;
    uint8_t *val;
} _tlv_t;

void _free_tlv(_tlv_t *data);

typedef struct _auth_reg_assertion_tlv {
    char *aaid;
    unsigned char *key_id;
    int key_id_len;
} _auth_reg_assertion_tlv_t;

void _free_auth_reg_assertion_tlv(_auth_reg_assertion_tlv_t *data);

typedef struct _response_ {
    _op_header_t *header;
    char *fcp;
    GList *assertion_list;
} _response_t;

void _free_response(_response_t *data);

typedef enum {
    _DBUS_OP_TYPE_INIT,
    _DBUS_OP_TYPE_DE_INIT,
    _DBUS_OP_TYPE_DISCOVER,
    _DBUS_OP_TYPE_CHECK_POLICY,
    _DBUS_OP_TYPE_PROCESS,
    _DBUS_OP_TYPE_NOTIFY
} _dbus_op_type_e;

typedef enum {
    _ASM_STATUS_OK = 0x00,
    _ASM_STATUS_ERROR = 0x01,
    _ASM_STATUS_ACCESS_DENIED = 0x02,
    _ASM_STATUS_USER_CANCELLED = 0x03
} _asm_status_e;

void _free_tc_disp_png_char(gpointer data);

void _free_asm_auth_list(gpointer data);

#define _CLIENT_VENDOR_NAME_MAX_SIZE 127
#define _CLIENT_VENDOR_NAME "samsung"
#define _CLIENT_VERSION_MAJOR 1
#define _CLIENT_VERSION_MINOR 0

#define _VERSION_MAJOR 1
#define _VERSION_MINOR 0

#define _INVALID_INT -1

#define _GET_INFO_ASM_REQUEST_JSON "{\"asmVersion\":{\"major\":1,\"minor\":0},\"requestType\":\"GetInfo\"}"

#define UI_DATA_ASM_ID "asm_id"
#define UI_DATA_AUTH_INDEX "auth"
#define UI_DATA_LABEL "label"
#define UI_DATA_ATT_TYPE "att"

#define _FIDO_DBUS_NAME "org.tizen.fido"
#define _FIDO_DBUS_PATH "/org/tizen/fido"

#define _FIDO_NO_CHANNEL_BINDING_DBUS_STRING "empty_channel_binding"
#define _FIDO_CID_KEY_UNUSED "unused"

#define _DBUS_TIMEOUT_INFINITE G_MAXINT
#define _DBUS_TIMEOUT_USE_DEFAULT -1

#define _EMPTY_JSON_STRING "{}"

#define _UI_IPC_KEY_REQ "ui_rq"

#define _UI_SVC_PACKAGE "org.tizen.fidosvcui"
#define _UI_SVC_BIN_PATH "/usr/apps/org.tizen.fidosvcui/bin/org.tizen.fidosvcui"

#endif // FIDO_INTERNAL_TYPES_H
