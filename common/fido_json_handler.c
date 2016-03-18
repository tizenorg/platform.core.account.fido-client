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


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlog.h>
#include <glib.h>
#if !GLIB_CHECK_VERSION (2, 31, 0)
#include <glib/gmacros.h>
#endif
#include <json-glib/json-glib.h>
#include "fido_internal_types.h"
#include "fido_json_handler.h"
#include "fido_keys.h"
#include "fido_logs.h"
#include "fido_uaf_types.h"
#include "fido_b64_util.h"
#include "fido_tlv_util.h"

/*JSON keys start*/
#define _JSON_KEY_ID "id"
#define _JSON_KEY_DATA "data"
#define _JSON_KEY_FAIL_IF_UNKNOWN "fail_if_unknown"
#define _JSON_KEY_EXTS "exts"
#define _JSON_KEY_UPV "upv"
#define _JSON_KEY_MAJOR "major"
#define _JSON_KEY_MINOR "minor"
#define _JSON_KEY_OP "op"
#define _JSON_KEY_APPID "appID"
#define _JSON_KEY_SERVER_DATA "serverData"
#define _JSON_KEY_AAID "aaid"
#define _JSON_KEY_VENDOR_ID "vendorID"
#define _JSON_KEY_KEY_IDS "keyIDs"
#define _JSON_KEY_USER_VERIFICATION "userVerification"
#define _JSON_KEY_KEY_PROTECTION "keyProtection"
#define _JSON_KEY_MATCHER_PROTECTION "matcherProtection"
#define _JSON_KEY_ATTACHMENT_HINT "attachmentHint"
#define _JSON_KEY_TC_DISPLAY "tcDisplay"
#define _JSON_KEY_AUTH_ALGOS "authenticationAlgorithms"
#define _JSON_KEY_AUTH_ALGO "authenticationAlgorithm"
#define _JSON_KEY_ASSERT_SCHEMES "assertionSchemes"
#define _JSON_KEY_ATT_TYPES "attestationTypes"
#define _JSON_KEY_ATT_TYPE "attestationType"
#define _JSON_KEY_AUTH_VERSION "authenticatorVersion"
#define _JSON_KEY_PLTE "plte"
#define _JSON_KEY_R "r"
#define _JSON_KEY_G "g"
#define _JSON_KEY_B "b"
#define _JSON_KEY_WIDTH "width"
#define _JSON_KEY_HEIGHT "height"
#define _JSON_KEY_BIT_DEPTH "bitDepth"
#define _JSON_KEY_COLOR_TYPE "colorType"
#define _JSON_KEY_COMPRESSION "compression"
#define _JSON_KEY_FILTER "filter"
#define _JSON_KEY_INTERLACE "interlace"
#define _JSON_KEY_TC_DISP_PNG_CHARS "tcDisplayPNGCharacteristics"
#define _JSON_KEY_RESP_DATA "responseData"
#define _JSON_KEY_AUTHENTICATORS "Authenticators"
#define _JSON_KEY_AUTHENTICATORS_SMALL "authenticators"
#define _JSON_KEY_AUTH_INDEX "authenticatorIndex"
#define _JSON_KEY_IS_USER_ENROLLED "isUserEnrolled"
#define _JSON_KEY_HAS_SETTINGS "hasSettings"
#define _JSON_KEY_AAID "aaid"
#define _JSON_KEY_IS_2_FACTOR_ONLY "isSecondFactorOnly"
#define _JSON_KEY_IS_ROAMING_AUTH "isRoamingAuthenticator"
#define _JSON_KEY_SUPPORTED_EXT_IDS "supportedExtensionIDs"
#define _JSON_KEY_TC_DISP_CONTENT_TYPE "tcDisplayContentType"
#define _JSON_KEY_TITLE "title"
#define _JSON_KEY_DESC "description"
#define _JSON_KEY_ICON "icon"
#define _JSON_KEY_STATUS_CODE "statusCode"
#define _JSON_KEY_ASSERTION "assertion"
#define _JSON_KEY_ASSERT_SCHEME "assertionScheme"
#define _JSON_KEY_CHALLENGE "challenge"
#define _JSON_KEY_CH_BINDING "channelBinding"
#define _JSON_KEY_SERVER_END_POINT "serverEndPoint"
#define _JSON_KEY_TLS_SERVER_CERT "tlsServerCertificate"
#define _JSON_KEY_TLS_UNIQUE "tlsUnique"
#define _JSON_KEY_CID_PUB_KEY "cid_pubkey"
#define _JSON_KEY_FACET_ID "facetID"
#define _JSON_KEY_HEADER "header"
#define _JSON_KEY_FC_PARAMS "fcParams"
#define _JSON_KEY_FINAL_CHALLENGE		"finalChallenge"
#define _JSON_KEY_ASSERTIONS "assertions"
#define _JSON_KEY_POLICY "policy"
#define _JSON_KEY_ACCEPTED "accepted"
#define _JSON_KEY_DISALLOWED "disallowed"
#define _JSON_KEY_USER_NAME "username"
#define _JSON_KEY_TRUSTED_FACETS "trustedFacets"
#define _JSON_KEY_VERSION "version"
#define _JSON_KEY_IDS "ids"
#define _JSON_KEY_APP_REGS "appRegs"
#define _JSON_KEY_REQ_TYPE	"requestType"
#define _JSON_KEY_KEY_ID		"keyID"
#define _JSON_KEY_TRANSACTION		"transaction"
#define _JSON_KEY_CONTENT_TYPE "contentType"
#define _JSON_KEY_CONTENT "content"
#define _JSON_KEY_REGISTER		"Register"
#define _JSON_KEY_AUTHENTICATE	"Authenticate"
#define _JSON_KEY_DEREGISTER		"Deregister"
#define _JSON_KEY_ASM_VERSION "asmVersion"
#define _JSON_KEY_GET_REGS "GetRegistrations"
#define _JSON_KEY_KTY "kty"
#define _JSON_KEY_CRV "crv"
#define _JSON_KEY_X "x"
#define _JSON_KEY_Y "y"
#define _JSON_KEY_ARGS		"args"

#define _JSON_KEY_VENDOR "vendor"
#define _JSON_KEY_BIN_PATH "bin_path"
#define _JSON_KEY_DBUS_INFO "dbus_info"
#define _JSON_KEY_DBUS_OBJ_PATH "dbus_obj_path"
#define _JSON_KEY_DBUS_INTF_NAME "dbus_interface_name"
#define _JSON_KEY_DBUS_METHOD_NAME "dbus_method_name"
/*JSON keys end*/

#ifdef WITH_JSON_BUILDER
static void
__add_string_to_json_object(JsonBuilder *json_obj, const char *key, const char *val)
{
    if (key == NULL || val == NULL)
        return;

    json_builder_set_member_name(json_obj, key);
    json_builder_add_string_value(json_obj, val);
}

static void
__add_int_to_json_object(JsonBuilder *json_obj, const char *key, int val)
{
    if (key == NULL || val == _INVALID_INT)
        return;

    json_builder_set_member_name(json_obj, key);
    json_builder_add_int_value(json_obj, val);
}
#endif

static gboolean
__uaf_composer_compose_asm_init(JsonGenerator **generator, JsonObject **root_obj)
{
    dlog_print(DLOG_INFO, "FIDO", "__uaf_composer_compose_asm_init");
    JsonNode *root_node = NULL;

    *generator = json_generator_new();
    if(*generator == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_generator_new is NULL");
    	goto CATCH;
    }

    root_node = json_node_new(JSON_NODE_OBJECT);
    if (root_node == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "*json_node_new is NULL");
    	goto CATCH;
    }

    *root_obj = json_object_new();
    if(*root_obj == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_object_new in NULL");
    	goto CATCH;
    }

    json_node_take_object(root_node, *root_obj);
    json_generator_set_root(*generator, root_node);

    return TRUE;


    CATCH:
    if (generator != NULL && *generator != NULL) {
    	g_object_unref(*generator);
    	*generator = NULL;
    }

    if (root_node != NULL) {
    	json_node_free(root_node);
    	root_node = NULL;
    }

    if (root_obj != NULL && *root_obj != NULL) {
    	g_object_unref(*root_obj);
    	*root_obj = NULL;
    }
    return FALSE;
}

static gboolean
__uaf_composer_compose_asm_response_init(JsonGenerator **generator, JsonObject **root_obj)
{
    dlog_print(DLOG_INFO, "FIDO", "__uaf_composer_compose_asm_init");
    JsonNode *root_node = NULL;
    JsonNode *gen_node = NULL;
    JsonObject *gen_object = NULL;
    JsonArray *rootArray = json_array_new();

    *generator = json_generator_new();
    if(*generator == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_generator_new is NULL");
    	goto CATCH;
    }

    gen_node = json_node_new(JSON_NODE_ARRAY);
    if (gen_node == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "*json_node_new is NULL");
    	goto CATCH;
    }
    
    root_node = json_node_new(JSON_NODE_OBJECT);
    if (root_node == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "*json_node_new is NULL");
    	goto CATCH;
    }

    gen_object = json_object_new();
    if(gen_object == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_object_new in NULL");
    	goto CATCH;
    }
    
    *root_obj = json_object_new();
    if(*root_obj == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_object_new in NULL");
    	goto CATCH;
    }

    json_node_take_object(root_node, *root_obj);
    json_array_add_element(rootArray, root_node);
    json_node_take_array(gen_node, rootArray);
    json_generator_set_root(*generator, gen_node);

    return TRUE;


    CATCH:
    if (generator != NULL && *generator != NULL) {
    	g_object_unref(*generator);
    	*generator = NULL;
    }

    if (gen_node != NULL) {
    	json_node_free(gen_node);
    	root_node = NULL;
    }
    
    if (root_node != NULL) {
    	json_node_free(root_node);
    	root_node = NULL;
    }
    
    if (root_obj != NULL && *root_obj != NULL) {
    	g_object_unref(*root_obj);
    	*root_obj = NULL;
    }
    return FALSE;
}

static gboolean
__uaf_composer_compose_asm_version(_version_t *version, JsonNode **node)
{
    dlog_print(DLOG_INFO, "FIDO", "__uaf_composer_compose_asm_version");
    if (!version && version->major && version->minor) {
    	dlog_print(DLOG_INFO, "FIDO", "invalid uaf version");
    	return FALSE;
    }

    *node = json_node_new(JSON_NODE_OBJECT);
    if (*node == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_node_new is NULL");
    	goto CATCH;
    }

    JsonObject *obj = json_object_new();
    if(obj == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_object_new in NULL");
    	goto CATCH;
    }

    json_object_set_int_member(obj, _JSON_KEY_MAJOR, version->major);
    json_object_set_int_member(obj, _JSON_KEY_MINOR, version->minor);

    json_node_take_object(*node, obj);

    return TRUE;

    CATCH:
    if (node !=NULL && *node != NULL) {
    	json_node_free(*node);
    	*node = NULL;
    }

    if (obj != NULL && obj != NULL) {
    	g_object_unref(obj);
    	obj = NULL;
    }
    return FALSE;
}

static gboolean
__uaf_composer_compose_asm_reg_in(_fido_asm_reg_in_t *reg_in, JsonNode **node)
{
    dlog_print(DLOG_INFO, "FIDO", "__uaf_composer_compose_asm_versiom");
    if (!reg_in) {
    	dlog_print(DLOG_INFO, "FIDO", "invalid uaf version");
    	return FALSE;
    }

    *node = json_node_new(JSON_NODE_OBJECT);
    if (*node == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_node_new is NULL");
    	goto CATCH;
    }

    JsonObject *obj = json_object_new();
    if(obj == NULL) {
    	dlog_print(DLOG_INFO, "FIDO", "json_object_new in NULL");
    	goto CATCH;
    }

    if (reg_in->app_id)
        json_object_set_string_member(obj, _JSON_KEY_APPID, reg_in->app_id);

    if (reg_in->user_name)
        json_object_set_string_member(obj, _JSON_KEY_USER_NAME, reg_in->user_name);

    if (reg_in->final_challenge)
        json_object_set_string_member(obj, _JSON_KEY_FINAL_CHALLENGE, reg_in->final_challenge);

    if (reg_in->attestation_type)
        json_object_set_int_member(obj, _JSON_KEY_ATT_TYPE, reg_in->attestation_type);

    json_node_take_object(*node, obj);

    return TRUE;

    CATCH:
    if (node != NULL && *node != NULL) {
    	json_node_free(*node);
    	*node = NULL;
    }

    if (obj != NULL && obj != NULL) {
    	g_object_unref(obj);
    	obj = NULL;
    }
    return FALSE;
}

static gboolean
__uaf_composer_compose_asm_auth_in(_fido_asm_auth_in_t *auth_in, JsonNode **node)
{
    dlog_print(DLOG_INFO, "FIDO", "__uaf_composer_compose_asm_auth_in");
    if (!auth_in) {
        dlog_print(DLOG_INFO, "FIDO", "invalid uaf version");
        return FALSE;
    }

    GList* iter;
    *node = json_node_new(JSON_NODE_OBJECT);
    if (*node == NULL) {
        dlog_print(DLOG_INFO, "FIDO", "json_node_new is NULL");
        goto CATCH;
    }

    JsonObject *obj = json_object_new();
    if(obj == NULL) {
        dlog_print(DLOG_INFO, "FIDO", "json_object_new in NULL");
        goto CATCH;
    }

    if (auth_in->app_id)
        json_object_set_string_member(obj, _JSON_KEY_APPID, auth_in->app_id);

    if (auth_in->key_ids) {
        JsonArray *ids = json_array_new();

    for (iter = auth_in->key_ids; iter != NULL; iter = g_list_next(iter)) {
            json_array_add_string_element(ids, (char *)iter->data);
    }

        json_object_set_array_member(obj, _JSON_KEY_KEY_IDS, ids);
    }

    if (auth_in->final_challenge)
        json_object_set_string_member(obj, _JSON_KEY_FINAL_CHALLENGE, auth_in->final_challenge);

    if(auth_in->trans_list != NULL) {
        JsonArray *transArray = json_array_new();
        GList *iter = g_list_first(auth_in->trans_list);
        while(iter != NULL) {
            _fido_asm_transaction_t *val = (_fido_asm_transaction_t*)(iter->data);
            JsonNode *transNode = json_node_new(JSON_NODE_OBJECT);
            JsonObject *transObject = json_object_new();

            json_object_set_string_member(transObject, _JSON_KEY_CONTENT_TYPE, val->content_type);
            json_object_set_string_member(transObject, _JSON_KEY_CONTENT, val->content);

            JsonNode *tcNode = json_node_new(JSON_NODE_OBJECT);
            JsonObject *tcObject = json_object_new();

            if(val->display_charac != NULL) {
                json_object_set_int_member(tcObject, _JSON_KEY_WIDTH, val->display_charac->width);
                json_object_set_int_member(tcObject, _JSON_KEY_HEIGHT, val->display_charac->height);
                json_object_set_int_member(tcObject, _JSON_KEY_BIT_DEPTH, val->display_charac->bit_depth);
                json_object_set_int_member(tcObject, _JSON_KEY_COLOR_TYPE, val->display_charac->color_type);
                json_object_set_int_member(tcObject, _JSON_KEY_COMPRESSION, val->display_charac->compression);
                json_object_set_int_member(tcObject, _JSON_KEY_FILTER, val->display_charac->filter);
                json_object_set_int_member(tcObject, _JSON_KEY_INTERLACE, val->display_charac->interlace);

                if(val->display_charac != NULL) {
                    JsonArray *plteArray = json_array_new();

                    GList *plte_iter = g_list_first(val->display_charac->plte);
                    while(plte_iter != NULL) {
                        _fido_asm_rgb_pallette_entry_t *plte = (_fido_asm_rgb_pallette_entry_t*)(plte_iter->data);
                        JsonNode *plteNode = json_node_new(JSON_NODE_OBJECT);
                        JsonObject *plteObject = json_object_new();

                        json_object_set_int_member(plteObject, _JSON_KEY_R, plte->r);
                        json_object_set_int_member(plteObject, _JSON_KEY_B, plte->b);
                        json_object_set_int_member(plteObject, _JSON_KEY_G, plte->g);

                        json_node_take_object(plteNode, plteObject);
                        json_array_add_element(plteArray, plteNode);

                        plte_iter = plte_iter->next;
                    }
                    json_object_set_array_member(tcObject, _JSON_KEY_PLTE, plteArray);
                }
                json_node_take_object(tcNode, tcObject);
                json_object_set_member(transObject, "tcDisplayPNGCharacterstics", tcNode);
            }
            json_node_take_object(transNode, transObject);
            json_array_add_element(transArray, transNode);
            iter = iter->next;
        }
        json_object_set_array_member(obj, _JSON_KEY_TRANSACTION, transArray);
    }

    json_node_take_object(*node, obj);

    return TRUE;

    CATCH:
    if (*node != NULL) {
        json_node_free(*node);
        *node = NULL;
    }

    if (obj != NULL && obj != NULL) {
        g_object_unref(obj);
        obj = NULL;
    }
    return FALSE;
}

static char*
__get_string_from_json_object(JsonObject *obj, const char *key)
{
    _INFO("__get_string_from_json_object [%s]", key);

    if (json_object_has_member(obj, key) == false)
        return NULL;

    const char *str = json_object_get_string_member(obj, key);
    _INFO("[%s] = [%s]", key, str);

    return strdup(str);
}

static int
__get_int_from_json_object(JsonObject *obj, const char *key)
{
    if (obj == NULL)
        return _INVALID_INT;

    if (json_object_has_member(obj, key) == false)
        return _INVALID_INT;

    int int_val = json_object_get_int_member(obj, key);
    dlog_print(DLOG_INFO, "FIDO", "[%s] = [%d]", key, int_val);

    return int_val;
}

static _extension_t *
__get_extension(JsonObject *ext_json_obj)
{
    RET_IF_FAIL(ext_json_obj != NULL, NULL);

    _extension_t *ext = (_extension_t*) calloc(1, sizeof(_extension_t));
    RET_IF_FAIL(ext != NULL, NULL);

    ext->id = __get_string_from_json_object(ext_json_obj, _JSON_KEY_ID);
    ext->data = __get_string_from_json_object(ext_json_obj, _JSON_KEY_DATA);
    ext->fail_if_unknown = json_object_get_boolean_member(ext_json_obj, _JSON_KEY_FAIL_IF_UNKNOWN);

    return ext;

}

static GList *
__get_extension_list(JsonObject *root_obj)
{
    RET_IF_FAIL(root_obj != NULL, NULL);

    JsonArray *ext_json_arr = json_object_get_array_member(root_obj, _JSON_KEY_EXTS);
    RET_IF_FAIL(ext_json_arr != NULL, NULL);

    int ext_arr_len = json_array_get_length(ext_json_arr);
    RET_IF_FAIL(ext_arr_len > 0, NULL);

    GList *ext_list = NULL;

    int i = 0;
    for (; i < ext_arr_len; i++) {
        JsonObject *ext_json_obj = json_array_get_object_element(ext_json_arr, i);
        if (ext_json_obj != NULL) {
            _extension_t *ext = __get_extension(ext_json_obj);
            if (ext != NULL)
                ext_list = g_list_append(ext_list, ext);
        }
    }

    return ext_list;
}

static _op_header_t*
__parse_uaf_header(JsonObject *header_obj)
{
    _INFO("__parse_uaf_header");

    _op_header_t *header = (_op_header_t *)calloc(1, sizeof(_op_header_t));

    header->version = (_version_t *)calloc(1, sizeof(_version_t));

    JsonObject *ver_obj = json_object_get_object_member(header_obj, _JSON_KEY_UPV);
    if (ver_obj == NULL) {
        _free_op_header(header);
        return NULL;
    }

    int major = __get_int_from_json_object(ver_obj, _JSON_KEY_MAJOR);
    int minor = __get_int_from_json_object(ver_obj, _JSON_KEY_MINOR);

    if (major == _INVALID_INT || minor == _INVALID_INT) {

        _free_op_header(header);
        return NULL;
    }

    _INFO("found valid version");

    header->version->major = major;
    header->version->minor = minor;

    header->operation = __get_string_from_json_object(header_obj, _JSON_KEY_OP);

    header->app_id = __get_string_from_json_object(header_obj, _JSON_KEY_APPID);

    header->server_data = __get_string_from_json_object(header_obj, _JSON_KEY_SERVER_DATA);

    header->ext_list = __get_extension_list(header_obj);

    return header;
}

static GList *
__get_string_list_from_json_array(JsonArray *json_arr)
{
    if (json_arr == NULL)
        return NULL;

    GList *list = NULL;

    int arr_len = json_array_get_length(json_arr);
    int i = 0;
    for (; i < arr_len; i++) {
        const char *str = json_array_get_string_element(json_arr, i);
        if (str != NULL)
            list = g_list_append(list, strdup(str));

    }

    return list;
}

static GList *
__get_int_list_from_json_array(JsonArray *json_arr)
{
    if (json_arr == NULL)
        return NULL;

    GList *list = NULL;

    int arr_len = json_array_get_length(json_arr);
    int i = 0;
    for (; i < arr_len; i++) {
        int val = json_array_get_int_element(json_arr, i);
        list = g_list_append(list, GINT_TO_POINTER(val));

    }

    return list;
}

static _match_criteria_t*
_uaf_parser_parse_match(JsonObject *match_obj)
{
    _INFO("_uaf_parser_parse_match");

    if (match_obj != NULL) {

        _match_criteria_t *match_criteria = (_match_criteria_t*)calloc(1, sizeof(_match_criteria_t));

        JsonArray *aaid_arr = json_object_get_array_member(match_obj, _JSON_KEY_AAID);
        if (aaid_arr != NULL) {
            match_criteria->aaid_list = __get_string_list_from_json_array(aaid_arr);
        }

        JsonArray *vendor_arr = json_object_get_array_member(match_obj, _JSON_KEY_VENDOR_ID);
        if (vendor_arr != NULL) {
            match_criteria->vendor_list = __get_string_list_from_json_array(vendor_arr);
        }

        JsonArray *key_id_arr = json_object_get_array_member(match_obj, _JSON_KEY_KEY_IDS);
        if (key_id_arr != NULL) {
            match_criteria->key_id_list = __get_string_list_from_json_array(key_id_arr);
        }

        match_criteria->user_verification = __get_int_from_json_object(match_obj, _JSON_KEY_USER_VERIFICATION);

        match_criteria->key_protection = __get_int_from_json_object(match_obj, _JSON_KEY_KEY_PROTECTION);

        match_criteria->matcher_protection = __get_int_from_json_object(match_obj, _JSON_KEY_MATCHER_PROTECTION);

        match_criteria->attachement_hint = __get_int_from_json_object(match_obj, _JSON_KEY_ATTACHMENT_HINT);

        match_criteria->tc_display = __get_int_from_json_object(match_obj, _JSON_KEY_TC_DISPLAY);


        JsonArray *auth_algo_arr = json_object_get_array_member(match_obj, _JSON_KEY_AUTH_ALGOS);
        if (auth_algo_arr) {
            match_criteria->auth_algo_list = __get_int_list_from_json_array(auth_algo_arr);
		}

        JsonArray *assertion_schm_arr = json_object_get_array_member(match_obj, _JSON_KEY_ASSERT_SCHEMES);
        if (assertion_schm_arr) {
            match_criteria->assertion_scheme_list = __get_string_list_from_json_array(assertion_schm_arr);
		}

        JsonArray *att_type_arr = json_object_get_array_member(match_obj, _JSON_KEY_ATT_TYPES);
        if (att_type_arr) {
            match_criteria->attestation_type_list = __get_string_list_from_json_array(att_type_arr);
        }

        match_criteria->auth_version = __get_int_from_json_object(match_obj, _JSON_KEY_AUTH_VERSION);

        _INFO("_uaf_parser_parse_match is returning match_criteria");

        return match_criteria;
	}

    _INFO("_uaf_parser_parse_match is returning NULL");
    return NULL;
}

static GList*
__get_plte_list(JsonObject *png_json_obj)
{

    _INFO("");

    GList *plte_list_priv = NULL;

    JsonArray *plte_json_arr = json_object_get_array_member(png_json_obj, "plte");
    RET_IF_FAIL(plte_json_arr != NULL, NULL);

    int plte_arr_len = json_array_get_length(plte_json_arr);
    RET_IF_FAIL(plte_arr_len > 0, NULL);

    int i = 0;
    for (; i < plte_arr_len; i++) {
        JsonObject *plte_json_obj = json_array_get_object_element(plte_json_arr, i);
        if (plte_json_obj != NULL) {
            fido_rgb_pallette_entry_s *pallete =
                    (fido_rgb_pallette_entry_s *) calloc(1, sizeof(fido_rgb_pallette_entry_s));

            if (pallete != NULL) {
                pallete->r = __get_int_from_json_object(plte_json_obj, _JSON_KEY_R);
                pallete->g = __get_int_from_json_object(plte_json_obj, _JSON_KEY_G);
                pallete->b = __get_int_from_json_object(plte_json_obj, _JSON_KEY_B);

                plte_list_priv = g_list_append(plte_list_priv, pallete);
            }

        }
    }

    if (plte_list_priv == NULL)
        return NULL;

    plte_list_priv = g_list_first(plte_list_priv);

    _INFO("");

    return plte_list_priv;
}

static fido_display_png_characteristics_descriptor_s *
__get_png_data(JsonObject *png_json_obj)
{
    RET_IF_FAIL(png_json_obj != NULL, NULL);

    _INFO("");

    fido_display_png_characteristics_descriptor_s *png_data = (fido_display_png_characteristics_descriptor_s*)
            calloc(1, sizeof(fido_display_png_characteristics_descriptor_s));

    png_data->width = __get_int_from_json_object(png_json_obj, _JSON_KEY_WIDTH);
    png_data->height = __get_int_from_json_object(png_json_obj, _JSON_KEY_HEIGHT);
    png_data->bit_depth = __get_int_from_json_object(png_json_obj, _JSON_KEY_BIT_DEPTH);
    png_data->color_type = __get_int_from_json_object(png_json_obj, _JSON_KEY_COLOR_TYPE);
    png_data->compression = __get_int_from_json_object(png_json_obj, _JSON_KEY_COMPRESSION);
    png_data->filter = __get_int_from_json_object(png_json_obj, _JSON_KEY_FILTER);
    png_data->interlace = __get_int_from_json_object(png_json_obj, _JSON_KEY_INTERLACE);

    png_data->plte = __get_plte_list(png_json_obj);

    _INFO("");
    return png_data;
}

static GList *
__get_tc_disp_png_array(JsonObject *auth_obj)
{
    RET_IF_FAIL(auth_obj != NULL, NULL);

    JsonArray *png_arr_json = json_object_get_array_member(auth_obj, _JSON_KEY_TC_DISP_PNG_CHARS);
    RET_IF_FAIL(png_arr_json != NULL, NULL);

    int arr_len = json_array_get_length(png_arr_json);
    RET_IF_FAIL(arr_len > 0, NULL);

    GList *png_list = NULL;
    int i = 0;
    for (; i < arr_len; i++) {
        JsonObject *png_json_obj = json_array_get_object_element(png_arr_json, i);
        if (png_json_obj != NULL) {

            fido_display_png_characteristics_descriptor_s *png = __get_png_data(png_json_obj);
            if (png != NULL)
                png_list = g_list_append(png_list, png);
        }
    }


    return png_list;
}

GList*
_uaf_parser_parse_asm_response_discover_client(char **asm_response_list, int len, int *error_code)
{
    _INFO("_uaf_parser_parse_asm_response_discover start");

    RET_IF_FAIL(asm_response_list != NULL, NULL);

    GList *available_authenticators = NULL;

    int i = 0;
    for (; i < len; i++) {

        JsonParser *parser = json_parser_new();
        CATCH_IF_FAIL(parser != NULL);

        GError *parse_err = NULL;
        json_parser_load_from_data(parser, asm_response_list[i], -1, &parse_err);
        CATCH_IF_FAIL(parse_err == NULL);

        JsonNode *root = json_parser_get_root(parser);
        CATCH_IF_FAIL(root != NULL);

        JsonObject *root_obj = json_node_get_object(root);
        CATCH_IF_FAIL(root_obj != NULL);

        int err_temp = 0;
        err_temp = json_object_get_int_member(root_obj, _JSON_KEY_STATUS_CODE);

        *error_code = err_temp;
        CATCH_IF_FAIL(*error_code == 0);

        JsonObject *response_obj = json_object_get_object_member(root_obj, _JSON_KEY_RESP_DATA);
        CATCH_IF_FAIL(response_obj != NULL);

        JsonArray *auth_arr = json_object_get_array_member(response_obj, _JSON_KEY_AUTHENTICATORS);
        CATCH_IF_FAIL(auth_arr != NULL);

        int auth_arr_len = json_array_get_length(auth_arr);

        int auth_arr_index = 0;
        for (auth_arr_index = 0; auth_arr_index < auth_arr_len; auth_arr_index++) {
            JsonObject *auth_obj = json_array_get_object_element(auth_arr, auth_arr_index);
            if (auth_obj != NULL) {
                fido_authenticator_s *auth_info = (fido_authenticator_s *)calloc(1, sizeof(fido_authenticator_s));


                int auth_index = json_object_get_int_member(auth_obj, _JSON_KEY_AUTH_INDEX);
                char *auth_idx_str = (char*)calloc(1, 128);
                snprintf(auth_idx_str, 127, "%d", auth_index);

                auth_info->auth_index = auth_idx_str;
                _INFO("auth_info->auth_index = [%s]", auth_info->auth_index);


                /* FIXME : ASM version list */

                bool is_enrolled = json_object_get_boolean_member(auth_obj, _JSON_KEY_IS_USER_ENROLLED);
                auth_info->is_user_enrolled = is_enrolled;

                bool has_settings = json_object_get_boolean_member(auth_obj, _JSON_KEY_HAS_SETTINGS);
                auth_info->has_settings = has_settings;


                const char *aaid = json_object_get_string_member(auth_obj, _JSON_KEY_AAID);
                if (aaid != NULL) {
                    auth_info->aaid = strdup(aaid);
                    _INFO("auth_info->aaid = [%s]", auth_info->aaid);
                }


                const char *assertion_schm = json_object_get_string_member(auth_obj, _JSON_KEY_ASSERT_SCHEME);
                if (assertion_schm != NULL)
                    auth_info->assertion_scheme = strdup(assertion_schm);

                int auth_algo  = json_object_get_int_member(auth_obj, _JSON_KEY_AUTH_ALGO);
                auth_info->authentication_algorithm = auth_algo;

                GList *att_list = NULL;
                JsonArray *att_arr = json_object_get_array_member(auth_obj, _JSON_KEY_ATT_TYPES);
                if (att_arr != NULL) {
                    int att_arr_len = json_array_get_length(att_arr);
                    int att_arr_idx = 0;
                    for (att_arr_idx = 0; att_arr_idx < att_arr_len; att_arr_idx++) {
                        int att = json_array_get_int_element(att_arr, att_arr_idx);
                        att_list = g_list_append(att_list, GINT_TO_POINTER(att));
                    }
                }

                if (att_list != NULL)
                    auth_info->attestation_types = g_list_first(att_list);

                int user_verification  = json_object_get_int_member(auth_obj, _JSON_KEY_USER_VERIFICATION);
                auth_info->user_verification = user_verification;

                int key_prot  = json_object_get_int_member(auth_obj, _JSON_KEY_KEY_PROTECTION);
                auth_info->key_protection = key_prot;


                int matcher_prot  = json_object_get_int_member(auth_obj, _JSON_KEY_MATCHER_PROTECTION);
                auth_info->matcher_protection = matcher_prot;

                int attch_hint  = json_object_get_int_member(auth_obj, _JSON_KEY_ATTACHMENT_HINT);
                auth_info->attachment_hint = attch_hint;


                bool is_sec_only  = json_object_get_boolean_member(auth_obj, _JSON_KEY_IS_2_FACTOR_ONLY);
                auth_info->is_second_factor_only = is_sec_only;


                bool is_roaming  = json_object_get_boolean_member(auth_obj, _JSON_KEY_IS_ROAMING_AUTH);
                auth_info->is_roaming = is_roaming;


                JsonArray *ext_id_json_arr = json_object_get_array_member(auth_obj, _JSON_KEY_SUPPORTED_EXT_IDS);
                if (ext_id_json_arr != NULL)
                    auth_info->supported_extension_IDs = __get_string_list_from_json_array(ext_id_json_arr);


                int tc_disp  = json_object_get_int_member(auth_obj, _JSON_KEY_TC_DISPLAY);
                auth_info->tc_display = tc_disp;

                const char *tc_dis_type = json_object_get_string_member(auth_obj, _JSON_KEY_TC_DISP_CONTENT_TYPE);
                if (tc_dis_type != NULL)
                    auth_info->tc_display_content_type = strdup(tc_dis_type);


                auth_info->tc_display_png_characteristics = __get_tc_disp_png_array(auth_obj);

                const  char *title = json_object_get_string_member(auth_obj, _JSON_KEY_TITLE);
                if (title != NULL)
                    auth_info->title = strdup(title);


                const char *desc = json_object_get_string_member(auth_obj, _JSON_KEY_DESC);
                if (desc != NULL)
                    auth_info->description = strdup(desc);


                const char *icon  = json_object_get_string_member(auth_obj, _JSON_KEY_ICON);
                if (icon != NULL)
                    auth_info->icon = strdup(icon);

                /* Supported UAF versions is fixed to 1.0*/
                 fido_version_s *version = calloc(1, sizeof(fido_version_s));
                 version->major = _VERSION_MAJOR;
                 version->minor = _VERSION_MINOR;

                 auth_info->supported_versions = g_list_append(auth_info->supported_versions, version);

                 available_authenticators = g_list_append(available_authenticators, auth_info);
            }
        }

        if (parser != NULL)
            g_object_unref(parser);

    }


    available_authenticators = g_list_first(available_authenticators);

    _INFO("available_authenticators count = [%d]", g_list_length(available_authenticators));

    return available_authenticators;

CATCH:
    return NULL;
}

GList*
_uaf_parser_parse_asm_response_discover(GList *asm_response_list, int *error_code)
{
    _INFO("_uaf_parser_parse_asm_response_discover start");

    RET_IF_FAIL(asm_response_list != NULL, NULL);

    GList *available_authenticators = NULL;

    GList *asm_response_list_iter = g_list_first(asm_response_list);
    while (asm_response_list_iter != NULL) {

        _asm_discover_response_t *asm_resp = (_asm_discover_response_t*)(asm_response_list_iter->data);
        if (asm_resp->error_code == FIDO_ERROR_NONE
                &&
                asm_resp->asm_response_json != NULL) {

            JsonParser *parser = json_parser_new();
            CATCH_IF_FAIL(parser != NULL);

            GError *parse_err = NULL;
            json_parser_load_from_data(parser, asm_resp->asm_response_json, -1, &parse_err);
            CATCH_IF_FAIL(parse_err == NULL);

            JsonNode *root = json_parser_get_root(parser);
            CATCH_IF_FAIL(root != NULL);

            JsonObject *root_obj = json_node_get_object(root);
            CATCH_IF_FAIL(root_obj != NULL);

            int err_temp = 0;
            err_temp = json_object_get_int_member(root_obj, _JSON_KEY_STATUS_CODE);

            *error_code = err_temp;
            CATCH_IF_FAIL(*error_code == 0);

            JsonObject *response_obj = json_object_get_object_member(root_obj, _JSON_KEY_RESP_DATA);
            CATCH_IF_FAIL(response_obj != NULL);

            JsonArray *auth_arr = json_object_get_array_member(response_obj, _JSON_KEY_AUTHENTICATORS);
            CATCH_IF_FAIL(auth_arr != NULL);

            int auth_arr_len = json_array_get_length(auth_arr);

            int auth_arr_index = 0;
            for (auth_arr_index = 0; auth_arr_index < auth_arr_len; auth_arr_index++) {
                JsonObject *auth_obj = json_array_get_object_element(auth_arr, auth_arr_index);
                if (auth_obj != NULL) {
                    fido_authenticator_s *auth_info = (fido_authenticator_s *)calloc(1, sizeof(fido_authenticator_s));


                    int auth_index = json_object_get_int_member(auth_obj, _JSON_KEY_AUTH_INDEX);
                    char *auth_idx_str = (char*)calloc(1, 128);
                    snprintf(auth_idx_str, 127, "%d", auth_index);

                    auth_info->auth_index = auth_idx_str;
                    _INFO("auth_info->auth_index = [%s]", auth_info->auth_index);


                    /* FIXME : ASM version list */

                    bool is_enrolled = json_object_get_boolean_member(auth_obj, _JSON_KEY_IS_USER_ENROLLED);
                    auth_info->is_user_enrolled = is_enrolled;

                    bool has_settings = json_object_get_boolean_member(auth_obj, _JSON_KEY_HAS_SETTINGS);
                    auth_info->has_settings = has_settings;


                    const char *aaid = json_object_get_string_member(auth_obj, _JSON_KEY_AAID);
                    if (aaid != NULL)
                        auth_info->aaid = strdup(aaid);


                    const char *assertion_schm = json_object_get_string_member(auth_obj, _JSON_KEY_ASSERT_SCHEME);
                    if (assertion_schm != NULL)
                        auth_info->assertion_scheme = strdup(assertion_schm);

                    int auth_algo  = json_object_get_int_member(auth_obj, _JSON_KEY_AUTH_ALGO);
                    auth_info->authentication_algorithm = auth_algo;

                    GList *att_list = NULL;
                    JsonArray *att_arr = json_object_get_array_member(auth_obj, _JSON_KEY_ATT_TYPES);
                    if (att_arr != NULL) {
                        int att_arr_len = json_array_get_length(att_arr);
                        int att_arr_idx = 0;
                        for (att_arr_idx = 0; att_arr_idx < att_arr_len; att_arr_idx++) {
                            int att = json_array_get_int_element(att_arr, att_arr_idx);
                            att_list = g_list_append(att_list, GINT_TO_POINTER(att));
                        }
                    }

                    if (att_list != NULL)
                        auth_info->attestation_types = g_list_first(att_list);

                    int user_verification  = json_object_get_int_member(auth_obj, _JSON_KEY_USER_VERIFICATION);
                    auth_info->user_verification = user_verification;

                    int key_prot  = json_object_get_int_member(auth_obj, _JSON_KEY_KEY_PROTECTION);
                    auth_info->key_protection = key_prot;


                    int matcher_prot  = json_object_get_int_member(auth_obj, _JSON_KEY_MATCHER_PROTECTION);
                    auth_info->matcher_protection = matcher_prot;

                    int attch_hint  = json_object_get_int_member(auth_obj, _JSON_KEY_ATTACHMENT_HINT);
                    auth_info->attachment_hint = attch_hint;


                    bool is_sec_only  = json_object_get_boolean_member(auth_obj, _JSON_KEY_IS_2_FACTOR_ONLY);
                    auth_info->is_second_factor_only = is_sec_only;


                    bool is_roaming  = json_object_get_boolean_member(auth_obj, _JSON_KEY_IS_ROAMING_AUTH);
                    auth_info->is_roaming = is_roaming;


                    JsonArray *ext_id_json_arr = json_object_get_array_member(auth_obj, _JSON_KEY_SUPPORTED_EXT_IDS);
                    if (ext_id_json_arr != NULL)
                        auth_info->supported_extension_IDs = __get_string_list_from_json_array(ext_id_json_arr);


                    int tc_disp  = json_object_get_int_member(auth_obj, _JSON_KEY_TC_DISPLAY);
                    auth_info->tc_display = tc_disp;

                    const char *tc_dis_type = json_object_get_string_member(auth_obj, _JSON_KEY_TC_DISP_CONTENT_TYPE);
                    if (tc_dis_type != NULL)
                        auth_info->tc_display_content_type = strdup(tc_dis_type);


                    auth_info->tc_display_png_characteristics = __get_tc_disp_png_array(auth_obj);

                    const char *title = json_object_get_string_member(auth_obj, _JSON_KEY_TITLE);
                    if (title != NULL)
                        auth_info->title = strdup(title);


                    const char *desc = json_object_get_string_member(auth_obj, _JSON_KEY_DESC);
                    if (desc != NULL)
                        auth_info->description = strdup(desc);


                    const char *icon  = json_object_get_string_member(auth_obj, _JSON_KEY_ICON);
                    if (icon != NULL)
                        auth_info->icon = strdup(icon);


                    if (asm_resp->asm_id != NULL)
                        auth_info->asm_id = strdup(asm_resp->asm_id);
                    else
                        _ERR("Authenticator does not have ASM ID!!");

                    available_authenticators = g_list_append(available_authenticators, auth_info);
                }
            }

            if (parser != NULL)
                g_object_unref(parser);

        }

        asm_response_list_iter = g_list_next(asm_response_list_iter);

    }


    available_authenticators = g_list_first(available_authenticators);

    _INFO("available_authenticators count = [%d]", g_list_length(available_authenticators));

    return available_authenticators;

CATCH:
    return NULL;
}

_asm_out_t*
_uaf_parser_parse_asm_response_reg(const char *asm_response_json, int *error_code)
{
	_INFO("_uaf_parser_parse_asm_response_reg[%s]", asm_response_json);

    _asm_out_t *asm_out = NULL;
    int status = 0;
    GError *parser_err = NULL;

    JsonParser *parser = json_parser_new();
    bool is_success = json_parser_load_from_data(parser, asm_response_json, -1, &parser_err);

    CATCH_IF_FAIL(is_success == true);

    JsonNode *root = json_parser_get_root(parser);
    CATCH_IF_FAIL(root != NULL);

    JsonObject *root_obj = json_node_get_object(root);
    CATCH_IF_FAIL(root_obj != NULL);

    status = json_object_get_int_member(root_obj, _JSON_KEY_STATUS_CODE);
    CATCH_IF_FAIL(status == 0);

    JsonObject *resp_obj = json_object_get_object_member(root_obj, _JSON_KEY_RESP_DATA);
    CATCH_IF_FAIL(resp_obj != NULL);

    const char *assertion = json_object_get_string_member(resp_obj, _JSON_KEY_ASSERTION);
    CATCH_IF_FAIL(assertion != NULL);

    const char *assertion_scheme = json_object_get_string_member(resp_obj, _JSON_KEY_ASSERT_SCHEME);
    CATCH_IF_FAIL(assertion_scheme != NULL);

    _asm_reg_out_t *reg_out = (_asm_reg_out_t*)calloc(1, sizeof(_asm_reg_out_t));
    reg_out->assertion = strdup(assertion);
    reg_out->assertion_schm = strdup(assertion_scheme);

    asm_out = (_asm_out_t*)calloc(1, sizeof(_asm_out_t));
    asm_out->type = _ASM_OUT_TYPE_REG;

    asm_out->status_code = status;
    asm_out->response_data = reg_out;

    asm_out->ext_list = __get_extension_list(root_obj);

    if (parser != NULL)
        g_object_unref(parser);

    *error_code = 0;
    return asm_out;

CATCH:
    _free_asm_out(asm_out);
    if (parser != NULL)
        g_object_unref(parser);

    *error_code = status;
    return NULL;
}

_asm_out_t*
_uaf_parser_parse_asm_response_auth(const char *asm_response_json, int *error_code)
{
    _asm_out_t *asm_out = NULL;
    int status = 0;
    GError *parser_err = NULL;

    JsonParser *parser = json_parser_new();
    bool is_success = json_parser_load_from_data(parser, asm_response_json, -1, &parser_err);

    CATCH_IF_FAIL(is_success == true);

    JsonNode *root = json_parser_get_root(parser);
    CATCH_IF_FAIL(root != NULL);

    JsonObject *root_obj = json_node_get_object(root);
    CATCH_IF_FAIL(root_obj != NULL);

    status = json_object_get_int_member(root_obj, _JSON_KEY_STATUS_CODE);
    CATCH_IF_FAIL(status == 0);

    JsonObject *resp_obj = json_object_get_object_member(root_obj, _JSON_KEY_RESP_DATA);
    CATCH_IF_FAIL(resp_obj != NULL);

    const char *assertion = json_object_get_string_member(resp_obj, _JSON_KEY_ASSERTION);
    CATCH_IF_FAIL(assertion != NULL);

    const char *assertion_scheme = json_object_get_string_member(resp_obj, _JSON_KEY_ASSERT_SCHEME);
    CATCH_IF_FAIL(assertion_scheme != NULL);

    _asm_auth_out_t *auth_out = (_asm_auth_out_t*)calloc(1, sizeof(_asm_auth_out_t));
    auth_out->assertion = strdup(assertion);
    auth_out->assertion_scheme = strdup(assertion_scheme);

    asm_out = (_asm_out_t*)calloc(1, sizeof(_asm_out_t));
    asm_out->type = _ASM_OUT_TYPE_AUTH;

    asm_out->status_code = status;
    asm_out->response_data = auth_out;

    asm_out->ext_list = __get_extension_list(root_obj);

    if (parser != NULL)
        g_object_unref(parser);

    *error_code = 0;
    return asm_out;

CATCH:
    _free_asm_out(asm_out);
    if (parser != NULL)
        g_object_unref(parser);

    *error_code = status;
    return NULL;
}

_asm_dereg_out_t*
_uaf_parser_parse_asm_response_dereg(const char *asm_response_json, int *error_code)
{
    _asm_dereg_out_t *asm_out = NULL;
    int status = 0;
    GError *parser_err = NULL;

    JsonParser *parser = json_parser_new();
    bool is_success = json_parser_load_from_data(parser, asm_response_json, -1, &parser_err);

    CATCH_IF_FAIL(is_success == true);

    JsonNode *root = json_parser_get_root(parser);
    CATCH_IF_FAIL(root != NULL);

    JsonObject *root_obj = json_node_get_object(root);
    CATCH_IF_FAIL(root_obj != NULL);

    asm_out = (_asm_dereg_out_t*)calloc(1, sizeof(_asm_dereg_out_t));

    asm_out->status_code = json_object_get_int_member(root_obj, _JSON_KEY_STATUS_CODE);

    if (parser != NULL)
        g_object_unref(parser);

    *error_code = 0;
    return asm_out;

CATCH:
    free(asm_out);
    if (parser != NULL)
        g_object_unref(parser);

    *error_code = status;
    return NULL;
}

int
_uaf_composer_compose_asm_reg_request(_version_t *version, int auth_index, _fido_asm_reg_in_t *reg_in, char **asm_reg_json)
{
    _INFO("_uaf_composer_compose_asm_reg_request start");

#ifdef WITH_JSON_BUILDER

    /*Builder start*/
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);

    /*requestType*/
    __add_string_to_json_object(builder, _JSON_KEY_REQ_TYPE, _JSON_KEY_REGISTER);

    /*version*/
    json_builder_set_member_name(builder, _JSON_KEY_ASM_VERSION);
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, _JSON_KEY_MAJOR);
    json_builder_add_int_value(builder, version->major);

    json_builder_set_member_name(builder, _JSON_KEY_MINOR);
    json_builder_add_int_value(builder, version->minor);

    json_builder_end_object(builder);
    /*version*/
    
    /*authIndex*/
    json_builder_set_member_name(builder, _JSON_KEY_AUTH_INDEX);
    json_builder_add_int_value(builder, auth_index);

    /*args*/
    json_builder_set_member_name(builder, _JSON_KEY_ARGS);
    json_builder_begin_object(builder);

    __add_string_to_json_object(builder, _JSON_KEY_APPID, reg_in->app_id);
    __add_string_to_json_object(builder, _JSON_KEY_USER_NAME, reg_in->user_name);
    __add_string_to_json_object(builder, _JSON_KEY_FINAL_CHALLENGE, reg_in->final_challenge);

    if (reg_in->attestation_type) {
        json_builder_set_member_name(builder, _JSON_KEY_ATT_TYPE);

        json_builder_add_int_value(builder, reg_in->attestation_type);
    }


    json_builder_end_object(builder);
    /*args*/


    json_builder_end_object(builder);
    /*Builder end*/

    JsonGenerator *gen = json_generator_new();
    JsonNode *root_builder = json_builder_get_root(builder);
    json_generator_set_root(gen, root_builder);

    json_node_free(root_builder);
    g_object_unref(builder);

    gsize len = 0;
    char *json = json_generator_to_data(gen, &len);
    if (json != NULL) {
        *asm_reg_json = json;

        if (gen != NULL)
            g_object_unref(gen);

        _INFO("asm_reg_req : %s", json);
        
        FILE *fp;
        fp = fopen("/tmp/asm_reg_request_3.0.txt", "w");
        fprintf(fp, "%s", json);
        fclose(fp);

        _INFO("_uaf_composer_compose_asm_reg_request end");

        return 0;
    }

    g_object_unref(gen);

    _INFO("_uaf_composer_compose_asm_reg_request fail");
    return -1;

#else
    _INFO("TIZEN-2.3.1");
    dlog_print(DLOG_INFO, "FIDO", "Composer _uaf_composer_compose_asm_reg_request");

    JsonNode *version_node = NULL;
    JsonNode *register_node = NULL;
    JsonGenerator *generator = json_generator_new();
    JsonObject *root_obj = json_object_new();

    if (!__uaf_composer_compose_asm_init(&generator, &root_obj)) {
        dlog_print(DLOG_INFO, "FIDO", "__uaf_composer_compose_asm_init fail");
        goto CATCH;
    }

    json_object_set_string_member(root_obj, _JSON_KEY_REQ_TYPE, _JSON_KEY_REGISTER);

    if (!__uaf_composer_compose_asm_version(version, &version_node)) {
        dlog_print(DLOG_INFO, "FIDO", "__uaf_composer_compose_asm_version fail");
        goto CATCH;
    }
    else
        json_object_set_member(root_obj, _JSON_KEY_ASM_VERSION, version_node);

    json_object_set_int_member(root_obj, _JSON_KEY_AUTH_INDEX, auth_index);

    if (!__uaf_composer_compose_asm_reg_in(reg_in, &register_node)) {
        dlog_print(DLOG_INFO, "FIDO", "__uaf_composer_compose_asm_reg_in fail");
        goto CATCH;
    }
    else
        json_object_set_member(root_obj, _JSON_KEY_ARGS, register_node);

    *asm_reg_json = json_generator_to_data(generator, NULL);

    FILE *fp;
    fp = fopen("/home/asm_reg_request_2.3.1.txt","w");
    fprintf(fp, "%s", *asm_reg_json);
    fclose(fp);

    if (generator != NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    return 0;

    CATCH:
    if (generator != NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    if (version_node != NULL) {
        json_node_free(version_node);
        version_node = NULL;
    }

    if (register_node != NULL) {
        json_node_free(register_node);
        register_node = NULL;
    }

    if (root_obj != NULL) {
        g_object_unref(root_obj);
        root_obj = NULL;
    }
    return -1;
#endif
}

int
_uaf_composer_compose_asm_auth_request(_version_t *version, int auth_index, _fido_asm_auth_in_t *auth_in,
                                       char **asm_auth_json)
{
    _INFO("_uaf_composer_compose_asm_auth_request start");

#ifdef WITH_JSON_BUILDER

	/*Builder start*/
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);

    /*requestType*/
    __add_string_to_json_object(builder, _JSON_KEY_REQ_TYPE, _JSON_KEY_AUTHENTICATE);

    /*authIndex*/
    json_builder_set_member_name(builder, _JSON_KEY_AUTH_INDEX);
    json_builder_add_int_value(builder, auth_index);

    /*version*/
    json_builder_set_member_name(builder, _JSON_KEY_ASM_VERSION);
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, _JSON_KEY_MAJOR);
    json_builder_add_int_value(builder, version->major);

    json_builder_set_member_name(builder, _JSON_KEY_MINOR);
    json_builder_add_int_value(builder, version->minor);

    json_builder_end_object(builder);
    /*version*/

    /*args*/
    json_builder_set_member_name(builder, _JSON_KEY_ARGS);
    json_builder_begin_object(builder);

    __add_string_to_json_object(builder, _JSON_KEY_APPID, auth_in->app_id);
    __add_string_to_json_object(builder, _JSON_KEY_FINAL_CHALLENGE, auth_in->final_challenge);

    if (auth_in->key_ids != NULL) {
        _INFO("keyID to be sent in ASM req");
        /*keyIDs*/
        json_builder_set_member_name(builder, _JSON_KEY_KEY_IDS);
        json_builder_begin_array(builder);

        GList *iter = g_list_first(auth_in->key_ids);
        while (iter != NULL) {

            char *val = (char*)(iter->data);
            json_builder_add_string_value(builder, val);
            iter = iter->next;
        }
        json_builder_end_array(builder);
        /*keyIDs*/
    }

    /*Transaction list composing*/
    if (auth_in->trans_list != NULL) {
        /*transaction*/
        json_builder_set_member_name(builder, _JSON_KEY_TRANSACTION);
        json_builder_begin_array(builder);

        GList *iter = g_list_first(auth_in->trans_list);
        while (iter != NULL) {

            _fido_asm_transaction_t *val = (_fido_asm_transaction_t*)(iter->data);
            /*transaction array element*/
            json_builder_begin_object(builder);

            /*contentType*/
            __add_string_to_json_object(builder, _JSON_KEY_CONTENT_TYPE, val->content_type);
            
            /*content*/
            __add_string_to_json_object(builder, _JSON_KEY_CONTENT, val->content);
            
            /*tcDisplayPNGCharacteristics*/
            if (val->display_charac != NULL) {
				
				json_builder_set_member_name(builder, "tcDisplayPNGCharacteristics");
                json_builder_begin_object(builder);

                __add_int_to_json_object(builder, _JSON_KEY_WIDTH, val->display_charac->width);
                __add_int_to_json_object(builder, _JSON_KEY_HEIGHT, val->display_charac->height);
                __add_int_to_json_object(builder, _JSON_KEY_BIT_DEPTH, val->display_charac->bit_depth);
                __add_int_to_json_object(builder, _JSON_KEY_COLOR_TYPE, val->display_charac->color_type);
                __add_int_to_json_object(builder, _JSON_KEY_COMPRESSION, val->display_charac->compression);
                __add_int_to_json_object(builder, _JSON_KEY_FILTER, val->display_charac->filter);
                __add_int_to_json_object(builder, _JSON_KEY_INTERLACE, val->display_charac->interlace);
                __add_int_to_json_object(builder, _JSON_KEY_WIDTH, val->display_charac->width);

                /*plte*/
                json_builder_set_member_name(builder, _JSON_KEY_PLTE);
                if (val->display_charac->plte != NULL) {

                    json_builder_begin_array(builder);

                    GList *plte_iter = g_list_first(val->display_charac->plte);
                    while (plte_iter != NULL) {
                        _fido_asm_rgb_pallette_entry_t *plte = (_fido_asm_rgb_pallette_entry_t*)(plte_iter->data);
                        
                        json_builder_begin_object(builder);
                        
                        __add_int_to_json_object(builder, _JSON_KEY_R, plte->r);
                        __add_int_to_json_object(builder, _JSON_KEY_G, plte->g);
                        __add_int_to_json_object(builder, _JSON_KEY_B, plte->b);
                        
                        json_builder_end_object(builder);

                        plte_iter = plte_iter->next;
                    }

                    json_builder_end_array(builder);
                }
                json_builder_end_object(builder);
            }

            json_builder_end_object(builder);

            iter = iter->next;
        }
        json_builder_end_array(builder);
        /*transaction*/
    }

    json_builder_end_object(builder);
    /*args*/


    json_builder_end_object(builder);
    /*Builder end*/

    JsonGenerator *gen = json_generator_new();
    JsonNode *root_builder = json_builder_get_root(builder);
    json_generator_set_root(gen, root_builder);

    json_node_free(root_builder);
    g_object_unref(builder);

    gsize len = 0;
    char *json = json_generator_to_data(gen, &len);
    if (json != NULL) {
        *asm_auth_json = json;

        if (gen != NULL)
            g_object_unref(gen);

        _INFO("%s", json);
        
        FILE *fp;
        fp = fopen("/tmp/asm_auth_request_3.0.txt", "w");
        fprintf(fp, "%s", json);
        fclose(fp);

        _INFO("_uaf_composer_compose_asm_auth_request end");

        return 0;
    }

    g_object_unref(gen);

    _INFO("_uaf_composer_compose_asm_auth_request fail");
    return -1;
    
#else
    JsonNode *version_node = NULL;
    JsonNode *auth_node = NULL;
    JsonGenerator *generator = json_generator_new();
    JsonObject *root_obj = json_object_new();

    if (!__uaf_composer_compose_asm_init(&generator, &root_obj)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_asm_auth_request fail");
        goto CATCH;
    }

    /*requestType*/
    json_object_set_string_member(root_obj, _JSON_KEY_REQ_TYPE, _JSON_KEY_AUTHENTICATE);

    /*authIndex*/
    json_object_set_int_member(root_obj, _JSON_KEY_AUTH_INDEX, auth_index);

    /*version*/
    if (!__uaf_composer_compose_asm_version(version, &version_node)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_asm_auth_request fail");
        goto CATCH;
    }
    else
        json_object_set_member(root_obj, _JSON_KEY_ASM_VERSION, version_node);

    /*args*/
    if (!__uaf_composer_compose_asm_auth_in(auth_in, &auth_node)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_asm_auth_request fail");
        goto CATCH;
    }
    else
        json_object_set_member(root_obj, _JSON_KEY_ARGS, auth_node);

    /*Transaction list composing*/

    *asm_auth_json = json_generator_to_data(generator, NULL);

    FILE *fp;
    fp = fopen("/home/asm_auth_request_2.3.1.txt","w");
    fprintf(fp, "%s", *asm_auth_json);
    fclose(fp);

    if (generator != NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    return 0;

CATCH:
    if (generator != NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    if (version_node != NULL) {
        json_node_free(version_node);
        version_node = NULL;
    }

    if (auth_node != NULL) {
        json_node_free(auth_node);
        auth_node = NULL;
    }

    if (root_obj != NULL) {
        g_object_unref(root_obj);
        root_obj = NULL;
    }
    return -1;
#endif
}

int
_uaf_composer_compose_asm_dereg_request(_version_t *version, int auth_index, _matched_auth_dereg_t *dereg_in,
                                        char **asm_dereg_json)
{
    _INFO("_uaf_composer_compose_asm_dereg_request start");

#ifdef WITH_JSON_BUILDER

	/*Builder start*/
    JsonBuilder *builder = json_builder_new();
    JsonBuilder *root = json_builder_begin_object(builder);

    /*requestType*/
    __add_string_to_json_object(root, _JSON_KEY_REQ_TYPE, _JSON_KEY_DEREGISTER);

    /*authIndex*/
    json_builder_set_member_name(root, _JSON_KEY_AUTH_INDEX);
    json_builder_add_int_value(root, auth_index);

    /*version*/
    json_builder_set_member_name(root, _JSON_KEY_ASM_VERSION);
    JsonBuilder *ver_root = json_builder_begin_object(root);
    json_builder_set_member_name(ver_root, _JSON_KEY_MAJOR);
    json_builder_add_int_value(ver_root, version->major);

    json_builder_set_member_name(ver_root, _JSON_KEY_MINOR);
    json_builder_add_int_value(ver_root, version->minor);

    json_builder_end_object(ver_root);


    /*args*/
    json_builder_set_member_name(root, _JSON_KEY_ARGS);
    JsonBuilder *args_root = json_builder_begin_object(root);

    __add_string_to_json_object(args_root, _JSON_KEY_APPID, dereg_in->app_id);
    __add_string_to_json_object(args_root, _JSON_KEY_KEY_ID, dereg_in->key_id);

    json_builder_end_object(args_root);

    json_builder_end_object(root);
    /*Builder end*/

    JsonGenerator *gen = json_generator_new();
    JsonNode *root_builder = json_builder_get_root(builder);
    json_generator_set_root(gen, root_builder);

    json_node_free(root_builder);
    g_object_unref(builder);

    gsize len = 0;
    char *json = json_generator_to_data(gen, &len);
    if (json != NULL) {
        *asm_dereg_json = json;
        _INFO("_uaf_composer_compose_uaf_process_response_reg return success");

        if (gen != NULL)
            g_object_unref(gen);

        _INFO("%s", json);
        
        FILE *fp;
        fp = fopen("/tmp/asm_dereg_request_3.0.txt", "w");
        fprintf(fp, "%s", json);
        fclose(fp);

        _INFO("_uaf_composer_compose_asm_dereg_request end");

        return 0;
    }

    g_object_unref(gen);

    _INFO("_uaf_composer_compose_asm_dereg_request fail");
    return -1;
 
#else

    JsonNode *version_node = NULL;
    JsonGenerator *generator = json_generator_new();
    JsonObject *root_obj = json_object_new();

    if (!__uaf_composer_compose_asm_init(&generator, &root_obj)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_asm_dereg_request fail");
        goto CATCH;
    }

    /*requestType*/
    json_object_set_string_member(root_obj, _JSON_KEY_REQ_TYPE, _JSON_KEY_DEREGISTER);

    /*authIndex*/
    json_object_set_int_member(root_obj, _JSON_KEY_AUTH_INDEX, auth_index);

    /*version*/
    if (!__uaf_composer_compose_asm_version(version, &version_node)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_asm_dereg_request fail");
        goto CATCH;
    }
    else
        json_object_set_member(root_obj, _JSON_KEY_ASM_VERSION, version_node);

    /*args*/
    JsonNode *argNode = json_node_new(JSON_NODE_OBJECT);
    JsonObject *argObject = json_object_new();

    json_object_set_string_member(argObject, _JSON_KEY_APPID, dereg_in->app_id);
    json_object_set_string_member(argObject, _JSON_KEY_KEY_ID, dereg_in->key_id);

    json_node_take_object(argNode, argObject);

    json_object_set_member(root_obj, _JSON_KEY_ARGS, argNode);

    gsize len = 0;
    char *json = json_generator_to_data(generator, &len);
    if (json != NULL) {
        *asm_dereg_json = json;
        _INFO("_uaf_composer_compose_uaf_process_response_reg return success");

        _INFO("%s", json);

        _INFO("_uaf_composer_compose_asm_dereg_request end");

        FILE *fp;
        fp = fopen("/home/asm_dereg_request_2.3.1.txt", "w");
        fprintf(fp, "%s", json);
        fclose(fp);
    }
    if (generator != NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    return 0;

CATCH:
    if (generator != NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    if (version_node != NULL) {
        json_node_free(version_node);
        version_node = NULL;
    }

    if (root_obj != NULL) {
        g_object_unref(root_obj);
        root_obj = NULL;
    }
    return -1;
#endif
}

//{"appID":"https://qa-egypt.noknoktest.com:443/UAFSampleProxy/uaf/facets.uaf","challenge":"uYBuGQf7r-LND16Q0GUpPRi112UjCtcym3awjm-MmmI","channelBinding":{},"facetID":"com.noknok.android.sampleapp"}
char *
_uaf_composer_compose_final_challenge(const char *app_id, const char *challenge, const char *facet_id, const char *ch_bin)
{
    _INFO("_uaf_composer_compose_final_challenge");

#ifdef WITH_JSON_BUILDER

    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);

    __add_string_to_json_object(builder, _JSON_KEY_APPID, app_id);

    __add_string_to_json_object(builder, _JSON_KEY_CHALLENGE, challenge);

    json_builder_set_member_name(builder, _JSON_KEY_CH_BINDING);
    json_builder_begin_object(builder);
    if (ch_bin != NULL) {

        JsonParser *chb_parser = json_parser_new();

        GError *chb_err = NULL;
        bool chb_parsed = json_parser_load_from_data(chb_parser, ch_bin, -1, &chb_err);
        if (chb_parsed == FALSE) {
            return NULL;
        }

        JsonNode *chb_root = json_parser_get_root(chb_parser);
        RET_IF_FAIL(chb_root != NULL, NULL);

        JsonObject *chb_root_obj = json_node_get_object(chb_root);
        RET_IF_FAIL(chb_root_obj != NULL, NULL);

        char *end_pt = __get_string_from_json_object(chb_root_obj, _JSON_KEY_SERVER_END_POINT);
        char *cert = __get_string_from_json_object(chb_root_obj, _JSON_KEY_TLS_SERVER_CERT);
        char *uni = __get_string_from_json_object(chb_root_obj, _JSON_KEY_TLS_UNIQUE);
        char *cid = __get_string_from_json_object(chb_root_obj, _JSON_KEY_CID_PUB_KEY);

        __add_string_to_json_object(builder, _JSON_KEY_SERVER_END_POINT, end_pt);
        __add_string_to_json_object(builder, _JSON_KEY_TLS_SERVER_CERT, cert);
        __add_string_to_json_object(builder, _JSON_KEY_TLS_UNIQUE, uni);
        __add_string_to_json_object(builder, _JSON_KEY_CID_PUB_KEY, cid);

        SAFE_DELETE(end_pt);
        SAFE_DELETE(cert);
        SAFE_DELETE(uni);
        SAFE_DELETE(cid);

        g_object_unref(chb_parser);

    }

    /*If no channledbinding to add, putting empty */
    json_builder_end_object(builder);

    __add_string_to_json_object(builder, _JSON_KEY_FACET_ID, facet_id);

    json_builder_end_object(builder);

    JsonNode *root_node = json_builder_get_root(builder);

    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, root_node);

    json_node_free(root_node);
    g_object_unref(builder);

    char *json_str = NULL;
    gsize len = 0;
    json_str = json_generator_to_data(generator, &len);

    if (json_str == NULL)
        return NULL;

    int inlen = strlen(json_str);
    int fc_enc_len = (4 * ((inlen + 2) / 3)) + 1;

    unsigned char *fc_enc = calloc(1, fc_enc_len);

    int r = _fido_b64url_encode((unsigned char*)json_str, inlen, fc_enc, &fc_enc_len);

    _INFO("_fido_b64url_encode len=[%d]", fc_enc_len);

    SAFE_DELETE(json_str);
    g_object_unref(generator);

    if (r != 0)
        return NULL;

    _INFO("_fido_b64url_encoded string=%s", fc_enc);

    return ((char*)fc_enc);
    
#else

    JsonGenerator *generator = json_generator_new();
    JsonObject *root_obj = json_object_new();

    if(!__uaf_composer_compose_asm_init(&generator, &root_obj)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_asm_init fail");
        goto CATCH;
    }

    json_object_set_string_member(root_obj, _JSON_KEY_APPID, app_id);
    json_object_set_string_member(root_obj, _JSON_KEY_CHALLENGE, challenge);

    JsonNode *jsonNode = NULL;
    JsonObject *jsonObject = json_object_new();

    if(ch_bin != NULL) {
        JsonParser *chb_parser = json_parser_new();

        GError *chb_err = NULL;
        bool chb_parsed = json_parser_load_from_data(chb_parser, ch_bin, -1, &chb_err);
        if (chb_parsed == FALSE) {
            return NULL;
        }

        JsonNode *chb_root = json_parser_get_root(chb_parser);
        if(chb_root == NULL) {
            return NULL;
        }

        JsonObject *chb_root_obj = json_node_get_object(chb_root);
        if(chb_root_obj == NULL) {
            return NULL;
        }

        char *end_pt = (char*)json_object_get_string_member(chb_root_obj, _JSON_KEY_SERVER_END_POINT);
        char *cert =(char*)json_object_get_string_member(chb_root_obj, _JSON_KEY_TLS_SERVER_CERT);
        char *uni = (char*)json_object_get_string_member(chb_root_obj, _JSON_KEY_TLS_UNIQUE);
        char *cid = (char*)json_object_get_string_member(chb_root_obj, _JSON_KEY_CID_PUB_KEY);

        json_object_set_string_member(jsonObject, _JSON_KEY_SERVER_END_POINT, end_pt);
        json_object_set_string_member(jsonObject, _JSON_KEY_TLS_SERVER_CERT, cert);
        json_object_set_string_member(jsonObject, _JSON_KEY_TLS_UNIQUE, uni);
        json_object_set_string_member(jsonObject, _JSON_KEY_CID_PUB_KEY, cid);

        SAFE_DELETE(end_pt);
        SAFE_DELETE(cert);
        SAFE_DELETE(uni);
        SAFE_DELETE(cid);

        g_object_unref(chb_parser);
    }

    /*If no channledbinding to add, putting empty*/
    json_node_take_object(jsonNode, jsonObject);
    json_object_set_member(root_obj, _JSON_KEY_CH_BINDING, jsonNode);

    char *json_str = NULL;
    gsize len = 0;
    json_str = json_generator_to_data(generator, &len);

    if (json_str == NULL)
        return NULL;

    int inlen = strlen(json_str);
    int fc_enc_len = (4 * ((inlen + 2) / 3)) + 1;

    unsigned char *fc_enc = calloc(1, fc_enc_len);

    int r = _fido_b64url_encode((unsigned char*)json_str, inlen, fc_enc, &fc_enc_len);

    _INFO("_fido_b64url_encode len=[%d]", fc_enc_len);

    SAFE_DELETE(json_str);
    g_object_unref(generator);

    if (r != 0)
        return NULL;

    _INFO("_fido_b64url_encoded string=%s", fc_enc);

    return ((char*)fc_enc);

CATCH:
    if(generator!=NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    if(root_obj!=NULL) {
        g_object_unref(root_obj);
        root_obj = NULL;
    }
    return NULL;
#endif
}

int
_uaf_composer_compose_uaf_process_response_reg(_op_header_t *header, char *final_ch, GList *assertions, char **uaf_response)
{
    _INFO("_uaf_composer_compose_uaf_process_response_reg");

#ifdef WITH_JSON_BUILDER

    RET_IF_FAIL(header != NULL, FIDO_ERROR_PROTOCOL_ERROR);

    /*Only 1.0 protocol support*/

    JsonBuilder *builder = json_builder_new();

    json_builder_begin_array(builder);

    json_builder_begin_object(builder);

    /* header*/
    json_builder_set_member_name(builder, _JSON_KEY_HEADER);
    json_builder_begin_object(builder);

    json_builder_set_member_name(builder, _JSON_KEY_APPID);
    json_builder_add_string_value(builder, header->app_id);

    json_builder_set_member_name(builder, _JSON_KEY_OP);
    json_builder_add_string_value(builder, header->operation);

    json_builder_set_member_name(builder, _JSON_KEY_SERVER_DATA);
    json_builder_add_string_value(builder, header->server_data);

    json_builder_set_member_name(builder, _JSON_KEY_UPV);
    json_builder_begin_object(builder);

    json_builder_set_member_name(builder, _JSON_KEY_MAJOR);
    json_builder_add_int_value(builder, header->version->major);

    json_builder_set_member_name(builder, _JSON_KEY_MINOR);
    json_builder_add_int_value(builder, header->version->minor);

    json_builder_end_object(builder);

    json_builder_end_object(builder);

    /* fcparams*/
    if (final_ch != NULL) {
        json_builder_set_member_name(builder, _JSON_KEY_FC_PARAMS);
        json_builder_add_string_value(builder, final_ch);
    }

    /* assertions*/
    json_builder_set_member_name(builder, _JSON_KEY_ASSERTIONS);
    json_builder_begin_array(builder);
    GList *assertions_iter = g_list_first(assertions);
    while (assertions_iter != NULL) {

        _auth_reg_assertion_t *ass_data = (_auth_reg_assertion_t*)(assertions_iter->data);
        json_builder_begin_object(builder);
        json_builder_set_member_name(builder, _JSON_KEY_ASSERTION);
        json_builder_add_string_value(builder, ass_data->assertion);

        json_builder_set_member_name(builder, _JSON_KEY_ASSERT_SCHEME);
        json_builder_add_string_value(builder, ass_data->assertion_schm);

		/*tcDisplayPNGCharacteristics*/
		if (ass_data->tc_disp_char_list != NULL) {
			json_builder_set_member_name(builder, "tcDisplayPNGCharacteristics");
			json_builder_begin_array(builder);

			GList *iter = g_list_first(ass_data->tc_disp_char_list);
			while (iter != NULL) {

				fido_display_png_characteristics_descriptor_s *png_data =
						(fido_display_png_characteristics_descriptor_s*) (iter->data);

				if (png_data != NULL) {

					json_builder_begin_object(builder);

					__add_int_to_json_object(builder, _JSON_KEY_WIDTH, png_data->width);
					__add_int_to_json_object(builder, _JSON_KEY_HEIGHT, png_data->height);
					__add_int_to_json_object(builder, _JSON_KEY_BIT_DEPTH, png_data->bit_depth);
					__add_int_to_json_object(builder, _JSON_KEY_COLOR_TYPE, png_data->color_type);
					__add_int_to_json_object(builder, _JSON_KEY_COMPRESSION, png_data->compression);
					__add_int_to_json_object(builder, _JSON_KEY_FILTER, png_data->filter);
					__add_int_to_json_object(builder, _JSON_KEY_INTERLACE, png_data->interlace);


					if (png_data->plte != NULL) {
						/*plte array start*/

						json_builder_set_member_name(builder, _JSON_KEY_PLTE);
						json_builder_begin_array(builder);

						GList *plte_iter = g_list_first(png_data->plte);
						while (plte_iter != NULL) {

							fido_rgb_pallette_entry_s *plte_data = (fido_rgb_pallette_entry_s*)(plte_iter->data);
							if (plte_data != NULL) {
								json_builder_begin_object(builder);

								__add_int_to_json_object(builder, _JSON_KEY_R, plte_data->r);
								__add_int_to_json_object(builder, _JSON_KEY_G, plte_data->g);
								__add_int_to_json_object(builder, _JSON_KEY_B, plte_data->b);

								json_builder_end_object(builder);
							}

							plte_iter = plte_iter->next;
						}

						json_builder_end_array(builder);

						/*plte array end*/
					}

					json_builder_end_object(builder);
				}

				iter = iter->next;
			}

			json_builder_end_array(builder);
		}

        json_builder_end_object(builder);

        assertions_iter = assertions_iter->next;

    }

    json_builder_end_array(builder);

    json_builder_end_object(builder);


    json_builder_end_array(builder);


    JsonNode *root_builder = json_builder_get_root(builder);

    JsonGenerator *gen = json_generator_new();
    json_generator_set_root(gen, root_builder);

    json_node_free(root_builder);
    g_object_unref(builder);

    gsize len = 0;
    char *json = json_generator_to_data(gen, &len);
    if (json != NULL) {
        *uaf_response = json;
        _INFO("_uaf_composer_compose_uaf_process_response_reg return success");
        
        FILE *fp;
        fp = fopen("/tmp/uaf_reg_auth_response_3.0.txt", "w");
        fprintf(fp, "%s", json);
        fclose(fp);

        if (gen != NULL)
            g_object_unref(gen);

        return FIDO_ERROR_NONE;
    }

    _INFO("_uaf_composer_compose_uaf_process_response_reg return fail");
    g_object_unref(gen);
    return FIDO_ERROR_PROTOCOL_ERROR;

#else
    
    JsonGenerator *generator = json_generator_new();
    JsonObject *root_obj = json_object_new();

    if(!__uaf_composer_compose_asm_response_init(&generator, &root_obj)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_asm_init fail");
        goto CATCH;
    }
 
    /*header*/
    JsonNode *_header = json_node_new(JSON_NODE_OBJECT);
    JsonObject *obj1 = json_object_new();
    if(obj1 == NULL) {
        dlog_print(DLOG_INFO, "FIDO", "json_object_new is NULL");
        goto CATCH;
    }

    json_object_set_string_member(obj1, _JSON_KEY_APPID, header->app_id);
    json_object_set_string_member(obj1, _JSON_KEY_OP, header->operation);
    json_object_set_string_member(obj1, _JSON_KEY_SERVER_DATA, header->server_data);

    JsonNode *upv = json_node_new(JSON_NODE_OBJECT);
    JsonObject *obj2 = json_object_new();
    if(obj2 == NULL) {
        dlog_print(DLOG_INFO, "FIDO", "json_object_new is NULL");
        goto CATCH;
    }

    json_object_set_int_member(obj2, _JSON_KEY_MAJOR, header->version->major);
    json_object_set_int_member(obj2, _JSON_KEY_MINOR, header->version->minor);

    json_node_take_object(upv, obj2);

    json_object_set_member(obj1, _JSON_KEY_UPV, upv);

    json_node_take_object(_header, obj1);
    json_object_set_member(root_obj, _JSON_KEY_HEADER, _header);

    /*fcparams*/

    json_object_set_string_member(root_obj, _JSON_KEY_FC_PARAMS, final_ch);
    _INFO("[LOG] final_ch = %s", final_ch);

    /*assertions*/
    JsonArray *assArray = json_array_new();
    GList *assertions_iter = g_list_first(assertions);
    while (assertions_iter != NULL) {

        _auth_reg_assertion_t *ass_data = (_auth_reg_assertion_t*)(assertions_iter->data);
        JsonNode *assNode = json_node_new(JSON_NODE_OBJECT);;
        JsonObject *assObject = json_object_new();
        json_object_set_string_member(assObject, _JSON_KEY_ASSERTION, ass_data->assertion);
        json_object_set_string_member(assObject, _JSON_KEY_ASSERT_SCHEME, ass_data->assertion_schm);

        /*tcDisplayPNGCharacteristics*/
        if (ass_data->tc_disp_char_list != NULL) {
            JsonArray *tcArray = json_array_new();
            GList *iter = g_list_first(ass_data->tc_disp_char_list);
            while (iter != NULL) {
                fido_display_png_characteristics_descriptor_s *png_data =
                        (fido_display_png_characteristics_descriptor_s*) (iter->data);

                if (png_data != NULL) {
                    JsonNode *tcNode = json_node_new(JSON_NODE_OBJECT);;
                    JsonObject *tcObject = json_object_new();

                    json_object_set_int_member(tcObject, _JSON_KEY_WIDTH, png_data->width);
                    json_object_set_int_member(tcObject, _JSON_KEY_HEIGHT, png_data->height);
                    json_object_set_int_member(tcObject, _JSON_KEY_BIT_DEPTH, png_data->bit_depth);
                    json_object_set_int_member(tcObject, _JSON_KEY_COLOR_TYPE, png_data->color_type);
                    json_object_set_int_member(tcObject, _JSON_KEY_COMPRESSION, png_data->compression);
                    json_object_set_int_member(tcObject, _JSON_KEY_FILTER, png_data->filter);
                    json_object_set_int_member(tcObject, _JSON_KEY_INTERLACE, png_data->interlace);

                    if (png_data->plte != NULL) {
                        /*plte array start*/
                        JsonArray *plteArray = json_array_new();
                        GList *plte_iter = g_list_first(png_data->plte);
                        while (plte_iter != NULL) {

                            fido_rgb_pallette_entry_s *plte_data = (fido_rgb_pallette_entry_s*)(plte_iter->data);
                            if (plte_data != NULL) {
                                JsonNode *plteNode = json_node_new(JSON_NODE_OBJECT);;
                                JsonObject *plteObject = json_object_new();
                                json_object_set_int_member(plteObject, _JSON_KEY_R, plte_data->r);
                                json_object_set_int_member(plteObject, _JSON_KEY_G, plte_data->g);
                                json_object_set_int_member(plteObject, _JSON_KEY_B, plte_data->b);

                                json_node_take_object(plteNode, plteObject);
                                json_array_add_element(plteArray, plteNode);
                            }
                            plte_iter = plte_iter->next;
                        }
                        json_object_set_array_member(tcObject, _JSON_KEY_PLTE, plteArray);
                    }
                    json_node_take_object(tcNode, tcObject);
                    json_array_add_element(tcArray, tcNode);
                }
                iter = iter->next;
            }
            json_object_set_array_member(assObject, "tcDisplayPNGCharacteristics", tcArray);
        }
        json_node_take_object(assNode, assObject);
        json_array_add_element(assArray, assNode);
        assertions_iter = assertions_iter->next;
    }
    json_object_set_array_member(root_obj, _JSON_KEY_ASSERTIONS, assArray);

    gsize len = 0;
    char *json = json_generator_to_data(generator, &len);
    if (json != NULL) {
        *uaf_response = json;
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_uaf_process_response_reg return success");
        _INFO("uaf_response=[%s]", json);

        FILE *fp;
        fp = fopen("/home/uaf_reg_auth_response_2.3.1.txt","w");
        fprintf(fp, "%s", json);
        fclose(fp);

        if (generator != NULL)
            g_object_unref(generator);

        return 0;
    }

    dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_uaf_process_response_reg return fail");

    if(generator!=NULL) {
        g_object_unref(generator);
        generator = NULL;
    }
    return 0;

CATCH:
    if(generator!=NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    if(root_obj!=NULL) {
        g_object_unref(root_obj);
        root_obj = NULL;
    }
    return -1;
#endif
}

int
_uaf_composer_compose_uaf_process_response_auth(_op_header_t *header, char *final_ch, GList *assertions, char **uaf_response)
{
    _INFO("_uaf_composer_compose_uaf_process_response_auth");
    return _uaf_composer_compose_uaf_process_response_reg(header, final_ch, assertions, uaf_response);
}

char *
_uaf_composer_compose_dereg_request(_response_t *uaf_res)
{
    _INFO("_uaf_composer_compose_dereg_request");

#ifdef WITH_JSON_BUILDER

    /*Only 1.0 protocol support*/

    JsonBuilder *builder = json_builder_new();

    JsonBuilder *root_array = json_builder_begin_array(builder);

    JsonBuilder *uaf_1_root = json_builder_begin_object(root_array);

    /* header*/
    json_builder_set_member_name(uaf_1_root, _JSON_KEY_HEADER);
    JsonBuilder *header_root = json_builder_begin_object(uaf_1_root);

    json_builder_set_member_name(header_root, _JSON_KEY_APPID);
    json_builder_add_string_value(header_root, uaf_res->header->app_id);

    json_builder_set_member_name(header_root, _JSON_KEY_OP);
    json_builder_add_string_value(header_root, strdup(_UAF_OPERATION_NAME_KEY_DE_REG));

    json_builder_set_member_name(header_root, _JSON_KEY_SERVER_DATA);
    json_builder_add_string_value(header_root, uaf_res->header->server_data);

    json_builder_set_member_name(header_root, _JSON_KEY_UPV);
    JsonBuilder *upv_root = json_builder_begin_object(header_root);

    json_builder_set_member_name(upv_root, _JSON_KEY_MAJOR);
    json_builder_add_int_value(upv_root, uaf_res->header->version->major);

    json_builder_set_member_name(upv_root, _JSON_KEY_MINOR);
    json_builder_add_int_value(upv_root,uaf_res->header->version->minor);

    json_builder_end_object(upv_root);

    json_builder_end_object(header_root);
    /* header*/

    _INFO("after header");


    /*appID*/
    if (uaf_res->header->app_id == NULL) {
        _ERR("appID is missing");

        g_object_unref(builder);
        return NULL;
    }

    json_builder_set_member_name(uaf_1_root, _JSON_KEY_APPID);
    json_builder_add_string_value(uaf_1_root, uaf_res->header->app_id);
    /*appID*/


    /*authenticators*/
    json_builder_set_member_name(uaf_1_root, _JSON_KEY_AUTHENTICATORS_SMALL);
    JsonBuilder *auth_root = json_builder_begin_array(uaf_1_root);
    GList *assertions_iter = g_list_first(uaf_res->assertion_list);
    while (assertions_iter != NULL) {

        _auth_reg_assertion_t *ass_data = (_auth_reg_assertion_t*)(assertions_iter->data);

        char *assrt = ass_data->assertion;

        _INFO("%s", assrt);

        _auth_reg_assertion_tlv_t *assrt_tlv = _tlv_util_decode_reg_assertion(assrt);
        if (assrt_tlv == NULL) {
            _ERR("Invalid assertion format");

            g_object_unref(builder);
            return NULL;
        }

        char *aaid = strdup(assrt_tlv->aaid);

        JsonBuilder *obj = json_builder_begin_object(auth_root);

        if (aaid != NULL) {
            json_builder_set_member_name(obj, _JSON_KEY_AAID);
            json_builder_add_string_value(obj, aaid);
            _INFO("aaid=[%s]", aaid);
        }

        if (assrt_tlv->key_id != NULL) {
            int inlen = assrt_tlv->key_id_len;
            int enc_len = (4 * ((inlen + 2) / 3)) + 1;

            unsigned char *key_id_enc = calloc(1, enc_len);

            int r = _fido_b64url_encode(assrt_tlv->key_id, inlen, key_id_enc, &enc_len);

            _INFO("_fido_b64url_encode len=[%d]", enc_len);

            if ((key_id_enc != NULL) && (r == 0)) {
                _INFO("_fido_b64url_encoded string=%s", key_id_enc);
                json_builder_set_member_name(obj, _JSON_KEY_KEY_ID);
                json_builder_add_string_value(obj, (char *)key_id_enc);
                _INFO("keyid=[%s]", key_id_enc);
            }

        }

        _INFO("after assertions");

        _free_auth_reg_assertion_tlv(assrt_tlv);

        json_builder_end_object(obj);


        assertions_iter = assertions_iter->next;

    }

    json_builder_end_array(auth_root);
    /*authenticators*/


    json_builder_end_object(uaf_1_root);


    json_builder_end_array(root_array);


    JsonNode *root_builder = json_builder_get_root(builder);
    JsonGenerator *gen = json_generator_new();
    json_generator_set_root(gen, root_builder);

    json_node_free(root_builder);
    g_object_unref(builder);

    gsize len = 0;
    char *dereg_json = json_generator_to_data(gen, &len);
    g_object_unref(gen);

    if (dereg_json != NULL) {
        _INFO("_uaf_composer_compose_dereg_request return success");
        _INFO("%s", dereg_json);
        
        FILE *fp;
        fp = fopen("/tmp/dereg_request_3.0.txt", "w");
        fprintf(fp, "%s", dereg_json);
        fclose(fp);
        
        return dereg_json;
    }

    _INFO("_uaf_composer_compose_dereg_request return fail");
    return NULL;
    
#else
    JsonGenerator *generator = json_generator_new();
    JsonObject *root_obj = json_object_new();

    if(!__uaf_composer_compose_asm_init(&generator, &root_obj)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compose_asm_init fail");
        goto CATCH;
    }

    /*header*/
    JsonNode *_headerNode = json_node_new(JSON_NODE_OBJECT);
    JsonObject *_headerObject = json_object_new();

    json_object_set_string_member(_headerObject, _JSON_KEY_APPID, uaf_res->header->app_id);
    json_object_set_string_member(_headerObject, _JSON_KEY_OP, strdup(_UAF_OPERATION_NAME_KEY_DE_REG));
    json_object_set_string_member(_headerObject, _JSON_KEY_SERVER_DATA, uaf_res->header->server_data);

    JsonNode *upvNode = json_node_new(JSON_NODE_OBJECT);
    JsonObject *upvObject = json_object_new();
    json_object_set_int_member(upvObject, _JSON_KEY_MAJOR, uaf_res->header->version->major);
    json_object_set_int_member(upvObject, _JSON_KEY_MINOR, uaf_res->header->version->minor);
    json_node_take_object(upvNode, upvObject);

    json_object_set_member(_headerObject, _JSON_KEY_UPV, upvNode);
    json_node_take_object(_headerNode, _headerObject);

    json_object_set_member(root_obj, _JSON_KEY_HEADER, _headerNode);
    /*header*/

    _INFO("after header");


    /*appID*/
    if (uaf_res->header->app_id == NULL) {
        _ERR("appID is missing");

        g_object_unref(generator);
        return NULL;
    }
    json_object_set_string_member(root_obj, _JSON_KEY_APPID, uaf_res->header->app_id);
    /*appID*/

    /*authenticators*/
    JsonArray *authArray = json_array_new();
    GList *assertions_iter = g_list_first(uaf_res->assertion_list);
    while (assertions_iter != NULL) {

        _auth_reg_assertion_t *ass_data = (_auth_reg_assertion_t*)(assertions_iter->data);

        char *assrt = ass_data->assertion;

        _INFO("%s", assrt);

        _auth_reg_assertion_tlv_t *assrt_tlv = _tlv_util_decode_reg_assertion(assrt);
        if (assrt_tlv == NULL) {
            _ERR("Invalid assertion format");

            g_object_unref(generator);
            return NULL;
        }

        char *aaid = strdup(assrt_tlv->aaid);
        JsonNode *authNode = json_node_new(JSON_NODE_OBJECT);
        JsonObject *authObject = json_object_new();

        if (aaid != NULL) {
            json_object_set_string_member(authObject, _JSON_KEY_AAID, aaid);
            _INFO("aaid=[%s]", aaid);
        }

        if (assrt_tlv->key_id != NULL) {
            int inlen = assrt_tlv->key_id_len;
            int enc_len = (4 * ((inlen + 2) / 3)) + 1;

            unsigned char *key_id_enc = calloc(1, enc_len);

            int r = _fido_b64url_encode(assrt_tlv->key_id, inlen, key_id_enc, &enc_len);

            _INFO("_fido_b64url_encode len=[%d]", enc_len);

            if ((key_id_enc != NULL) && (r == 0)) {

                _INFO("_fido_b64url_encoded string=%s", key_id_enc);
                json_object_set_string_member(authObject, _JSON_KEY_KEY_ID, (char *)key_id_enc);
                _INFO("keyid=[%s]", key_id_enc);
            }
        }
        json_node_take_object(authNode, authObject);
        json_array_add_element(authArray, authNode);
        assertions_iter = assertions_iter->next;
    }
    json_object_set_array_member(root_obj, _JSON_KEY_AUTHENTICATORS_SMALL, authArray);
    /*authenticators*/

    gsize len = 0;
    char *dereg_json = json_generator_to_data(generator, &len);
    if(generator!=NULL) {
        g_object_unref(generator);
        generator = NULL;
    }
    if (dereg_json != NULL) {
        _INFO("_uaf_composer_compose_dereg_request return success");
        _INFO("%s", dereg_json);

        FILE *fp;
        fp = fopen("/tmp/dereg_request_2.3.1.txt", "w");
        fprintf(fp, "%s", dereg_json);
        fclose(fp);

        return dereg_json;
    }

    return NULL;

CATCH:
    if(generator!=NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    if(root_obj!=NULL) {
        g_object_unref(root_obj);
        root_obj = NULL;
    }
    _INFO("_uaf_composer_compose_dereg_request return fail");
    return NULL;
#endif
}

static _policy_t*
__get_policy(JsonObject *uaf_object)
{
    /*TODO : Check in spec whether accepted array can be NULL, i.e allow all?*/

    JsonObject *policy_obj = json_object_get_object_member(uaf_object, _JSON_KEY_POLICY);
    RET_IF_FAIL(policy_obj != NULL, NULL);

    JsonArray *accepted_array = json_object_get_array_member(policy_obj, _JSON_KEY_ACCEPTED);
    RET_IF_FAIL(accepted_array != NULL, NULL);

    int accepted_len = json_array_get_length(accepted_array);
   _INFO("Parser accepted list count [%d]", accepted_len);

    _policy_t *policy_info = (_policy_t *)calloc(1, sizeof(_policy_t));
    policy_info->is_keyid_present = false;

    GList *allowed_list = NULL;

    int i = 0;
    for (i = 0; i < accepted_len; i++) {

        JsonArray *accepted_arr_inner = json_array_get_array_element(accepted_array, i);
        if (accepted_arr_inner) {
            int accepted_len_inner = json_array_get_length(accepted_arr_inner);
            _INFO("Parser accepted list inner count [%d]", accepted_len_inner);

            int j = 0;
            for (j = 0; j < accepted_len_inner; j++) {
                GList *allowed_list_inner = NULL;

                JsonObject *match_obj = json_array_get_object_element(accepted_arr_inner, j);
                if (match_obj) {
                    _match_criteria_t *match_info = _uaf_parser_parse_match(match_obj);
                    if (match_info) {
                        _INFO("Appending match_info");
                        if (policy_info->is_keyid_present == false) {
                            if (match_info->key_id_list != NULL)
                                policy_info->is_keyid_present = true;
                        }
                        allowed_list_inner = g_list_append(allowed_list_inner, match_info);
                    }
                }
                if (j == (accepted_len_inner - 1)) {
                    if (allowed_list_inner) {
                        _INFO("Appending accepted list");
                        allowed_list = g_list_append(allowed_list, allowed_list_inner);
                    }
                }
            }
        }
    }

    if (allowed_list != NULL)
        policy_info->accepted_list = g_list_first(allowed_list);

    GList *disallowed_list = NULL;

    JsonArray *disallowed_array = json_object_get_array_member(policy_obj, _JSON_KEY_DISALLOWED);
    if (disallowed_array != NULL) {
        int disallowed_len = json_array_get_length(disallowed_array);

        for (i = 0; i < disallowed_len; i++) {
            JsonObject *match_obj = json_array_get_object_element(disallowed_array, i);
            if (match_obj) {

                _match_criteria_t *match_info = _uaf_parser_parse_match(match_obj);
                if (match_info) {
                    if (policy_info->is_keyid_present == false) {
                        if (match_info->key_id_list != NULL)
                            policy_info->is_keyid_present = true;
                    }
                    disallowed_list = g_list_append(disallowed_list, match_info);
                }
            }
        }

        if (disallowed_list != NULL)
            policy_info->disallowed_list = g_list_first(disallowed_list);
    }

    _INFO("returning policy [%p]", policy_info);
    return policy_info;
}

static _reg_request_t*
__parse_uaf_reg_message(JsonObject *uaf_object)
{
        _reg_request_t *reg_req_temp = (_reg_request_t *)calloc(1, sizeof(_reg_request_t));

        reg_req_temp->challenge = __get_string_from_json_object(uaf_object, _JSON_KEY_CHALLENGE);

        reg_req_temp->user_name = __get_string_from_json_object(uaf_object, _JSON_KEY_USER_NAME);

        reg_req_temp->policy = __get_policy(uaf_object);
        if (reg_req_temp->policy != NULL)
            _INFO("parsed policy [%p]", reg_req_temp->policy);
        else
            _INFO("parsed policy [NULL]");

        return reg_req_temp;
}

static GList*
__get_transaction_list(JsonObject *uaf_obj)
{
    RET_IF_FAIL(uaf_obj != NULL, NULL);

    JsonArray *tr_arr = json_object_get_array_member(uaf_obj, _JSON_KEY_TRANSACTION);
    RET_IF_FAIL(tr_arr != NULL, NULL);

    _INFO("");

    GList *trans_list = NULL;

    int tr_arr_len = json_array_get_length(tr_arr);
    int i = 0;
    for (; i< tr_arr_len; i++) {
        JsonObject *tr_obj = json_array_get_object_element(tr_arr, i);
        if (tr_obj != NULL) {

            _auth_transaction_t *trans = calloc(1, sizeof(_auth_transaction_t));

            trans->content_type = __get_string_from_json_object(tr_obj, _JSON_KEY_CONTENT_TYPE);
            trans->content = __get_string_from_json_object(tr_obj, _JSON_KEY_CONTENT);

            /*tcDisplayPNGCharacteristics*/
            JsonObject *tc_disp_obj = json_object_get_object_member(tr_obj, _JSON_KEY_TC_DISP_PNG_CHARS);
            if (tc_disp_obj != NULL) {
                trans->display_charac = __get_png_data(tr_obj);
            }

            trans_list = g_list_append(trans_list, trans);
        }
    }

    if (trans_list != NULL) {
        trans_list = g_list_first(trans_list);
        _INFO("Transaction list count = [%d]", g_list_length(trans_list));
    }

    _INFO("");
    return trans_list;
}

static _auth_request_t*
__parse_uaf_auth_message(JsonObject *uaf_object)
{
    _auth_request_t *auth_req_temp = (_auth_request_t *)calloc(1, sizeof(_auth_request_t));

    auth_req_temp->challenge = __get_string_from_json_object(uaf_object, _JSON_KEY_CHALLENGE);

    auth_req_temp->transaction_list = __get_transaction_list(uaf_object);

    auth_req_temp->policy = __get_policy(uaf_object);

    if (auth_req_temp->policy != NULL)
        _INFO("parsed policy [%p]", auth_req_temp->policy);
    else
        _INFO("parsed policy [NULL]");

    return auth_req_temp;
}

static void
__dereg_auth_parser(JsonArray *array, guint index_, JsonNode *element_node, gpointer user_data)
{
     _dereg_request_t *dereg_req_temp = (_dereg_request_t *)user_data;

     JsonObject *auth_obj = json_node_get_object(element_node);
     if (auth_obj != NULL) {
         _dereg_auth_info_t *dereg_auth = (_dereg_auth_info_t*)calloc(1, sizeof(_dereg_auth_info_t));

         dereg_auth->aaid = __get_string_from_json_object(auth_obj, _JSON_KEY_AAID);
         dereg_auth->key_id = __get_string_from_json_object(auth_obj, _JSON_KEY_KEY_ID);

         dereg_req_temp->auth_info_list = g_list_append(dereg_req_temp->auth_info_list, dereg_auth);
     }
}

static _dereg_request_t*
__parse_uaf_dereg_message(JsonObject *uaf_object)
{
    _dereg_request_t *dereg_req_temp = (_dereg_request_t *)calloc(1, sizeof(_dereg_request_t));

    JsonArray *auth_arr = json_object_get_array_member(uaf_object, _JSON_KEY_AUTHENTICATORS_SMALL);
    if (auth_arr != NULL) {
        json_array_foreach_element(auth_arr, __dereg_auth_parser, dereg_req_temp);
    }

    return dereg_req_temp;
}

_message_t *
_uaf_parser_parse_message(const char *uaf_json, const gchar *channel_binding)
{
    _INFO("_uaf_parser_parse_message");

    RET_IF_FAIL(uaf_json != NULL, NULL);

    _message_t *uaf_message_temp = (_message_t*) calloc(1, sizeof(_message_t));
    uaf_message_temp->type = _MESSAGE_TYPE_MIN;

    if (channel_binding != NULL) {
        if (strcmp(channel_binding, _FIDO_NO_CHANNEL_BINDING_DBUS_STRING) != 0)
            uaf_message_temp->channel_binding = strdup(channel_binding);
    }

    JsonParser *parser = json_parser_new();
    CATCH_IF_FAIL(parser != NULL);

    GError *parse_err = NULL;
    json_parser_load_from_data(parser, uaf_json, -1, &parse_err);
    CATCH_IF_FAIL(parse_err == NULL);

    JsonNode *root = json_parser_get_root(parser);
    CATCH_IF_FAIL(root != NULL);

    JsonArray *uaf_array = json_node_get_array(root);
    CATCH_IF_FAIL(uaf_array != NULL);

    /* Parse all and accept only 1.0 version */

    int uaf_arr_len = json_array_get_length(uaf_array);
    if (uaf_arr_len <= 0) {
        _ERR("No UAF message found");

        _free_message(uaf_message_temp);
        g_object_unref(parser);
        return NULL;
    }

    int i = 0;
    for (; i < uaf_arr_len ; i++) {
        JsonObject *uaf_object = json_array_get_object_element(uaf_array, i);
        CATCH_IF_FAIL(uaf_object != NULL);

        JsonObject *header_obj = json_object_get_object_member(uaf_object, _JSON_KEY_HEADER);
        CATCH_IF_FAIL(header_obj != NULL);

        uaf_message_temp->header = __parse_uaf_header(header_obj);

        /* NULL signifies the header version is not 1.0 */
        if (uaf_message_temp->header == NULL)
            continue;

        if (strcmp(uaf_message_temp->header->operation, _UAF_OPERATION_NAME_KEY_REG) == 0){
            uaf_message_temp->data = (void *)__parse_uaf_reg_message(uaf_object);
            if (uaf_message_temp->data == NULL) {

                _free_message(uaf_message_temp);
                g_object_unref(parser);

                return NULL;
            }
            else {
                uaf_message_temp->type = _MESSAGE_TYPE_REG;

                g_object_unref(parser);

                return uaf_message_temp;
            }
        }

        if (strcmp(uaf_message_temp->header->operation, _UAF_OPERATION_NAME_KEY_AUTH) == 0){
            uaf_message_temp->data = (void *)__parse_uaf_auth_message(uaf_object);
            if (uaf_message_temp->data == NULL) {

                _free_message(uaf_message_temp);
                g_object_unref(parser);

                return NULL;
            }
            else {
               uaf_message_temp->type = _MESSAGE_TYPE_AUTH;

               g_object_unref(parser);
               return uaf_message_temp;

            }
        }

        if (strcmp(uaf_message_temp->header->operation, _UAF_OPERATION_NAME_KEY_DE_REG) == 0){
            uaf_message_temp->data = (void *)__parse_uaf_dereg_message(uaf_object);
            if (uaf_message_temp->data == NULL) {

                _free_message(uaf_message_temp);
                g_object_unref(parser);

                return NULL;
            }
            else {
                uaf_message_temp->type = _MESSAGE_TYPE_DEREG;

                g_object_unref(parser);
                return uaf_message_temp;
            }
        }

    }

CATCH:
    _free_message(uaf_message_temp);
    if (parser != NULL)
        g_object_unref(parser);

    return NULL;
}

GList *
_uaf_parser_parse_trusted_facets(const char *json)
{
    JsonParser *parser = json_parser_new();

    gsize len = -1;
    GError *err = NULL;

    GList *app_id_list = NULL;

    bool is_parsed = json_parser_load_from_data(parser, json, len, &err);
    CATCH_IF_FAIL(is_parsed == TRUE);


    JsonNode *root = json_parser_get_root(parser);

    JsonObject *root_obj = json_node_get_object(root);
    CATCH_IF_FAIL(root_obj != NULL);

    JsonArray *facet_arr = json_object_get_array_member(root_obj, _JSON_KEY_TRUSTED_FACETS);
    CATCH_IF_FAIL(facet_arr != NULL);

    int facet_arr_len = json_array_get_length(facet_arr);

    int i = 0;
    for (; i < facet_arr_len; i++) {
        JsonObject *facet_obj = json_array_get_object_element(facet_arr, i);
        if (facet_obj != NULL) {

            JsonObject *ver_obj = json_object_get_object_member(facet_obj, _JSON_KEY_VERSION);
            if (ver_obj != NULL) {
                int major = _INVALID_INT;
                int minor = _INVALID_INT;

                major = json_object_get_int_member(ver_obj, _JSON_KEY_MAJOR);
                minor = json_object_get_int_member(ver_obj, _JSON_KEY_MINOR);

                if (major == _VERSION_MAJOR && minor == _VERSION_MINOR) {
                    JsonArray *id_arr = json_object_get_array_member(facet_obj, _JSON_KEY_IDS);
                    if (id_arr != NULL) {
                        int id_arr_len = json_array_get_length(id_arr);

                        int idx = 0;
                        for (; idx < id_arr_len; idx++) {
                            const char *id = json_array_get_string_element(id_arr, idx);
                            if (id != NULL) {
                                app_id_list = g_list_append(app_id_list, strdup(id));
                            }
                        }
                    }
                }
            }
        }
    }

CATCH:
    if (parser != NULL)
        g_object_unref(parser);

    if (app_id_list != NULL)
        app_id_list = g_list_first(app_id_list);

    return app_id_list;
}

_response_t*
_uaf_parser_parse_uaf_response(const char *uaf_response)
{
    RET_IF_FAIL(uaf_response != NULL, NULL);

    _response_t *uaf_res_temp = (_response_t*) calloc(1, sizeof(_response_t));

    JsonParser *parser = json_parser_new();
    CATCH_IF_FAIL(parser != NULL);

    GError *parse_err = NULL;
    json_parser_load_from_data(parser, uaf_response, -1, &parse_err);
    CATCH_IF_FAIL(parse_err == NULL);

    JsonNode *root = json_parser_get_root(parser);
    CATCH_IF_FAIL(root != NULL);

    JsonArray *uaf_array = json_node_get_array(root);
    CATCH_IF_FAIL(uaf_array != NULL);

    /* Parse all and accept only 1.0 version */

    int uaf_arr_len = json_array_get_length(uaf_array);
    CATCH_IF_FAIL(uaf_arr_len > 0);

    int i = 0;
    for (; i < uaf_arr_len ; i++) {
        JsonObject *uaf_object = json_array_get_object_element(uaf_array, i);
        CATCH_IF_FAIL(uaf_object != NULL);

        JsonObject *header_obj = json_object_get_object_member(uaf_object, _JSON_KEY_HEADER);
        CATCH_IF_FAIL(header_obj != NULL);

        uaf_res_temp->header = __parse_uaf_header(header_obj);

        /* NULL signifies the header version is not 1.0 */
        if (uaf_res_temp->header == NULL)
            continue;

        char *op = uaf_res_temp->header->operation;

        /*Only process reg and auth responses*/
        if ((strcmp(op, _UAF_OPERATION_NAME_KEY_REG) != 0)
                && (strcmp(op, _UAF_OPERATION_NAME_KEY_AUTH) != 0)) {
            goto CATCH;
        }

        uaf_res_temp->fcp = __get_string_from_json_object(uaf_object, _JSON_KEY_FC_PARAMS);

        JsonArray *assrt_json_arr = json_object_get_array_member(uaf_object, _JSON_KEY_ASSERTIONS);
        CATCH_IF_FAIL(assrt_json_arr != NULL);

        int assrt_arr_len = json_array_get_length(assrt_json_arr);
        int i = 0;
        for (; i < assrt_arr_len; i++) {
            JsonObject *assrt_json_obj = json_array_get_object_element(assrt_json_arr, i);
            if (assrt_json_obj != NULL) {

                _auth_reg_assertion_t *assrt_data = (_auth_reg_assertion_t*)calloc(1, sizeof(_auth_reg_assertion_t));
                assrt_data->assertion = __get_string_from_json_object(assrt_json_obj, _JSON_KEY_ASSERTION);
                assrt_data->assertion_schm = __get_string_from_json_object(assrt_json_obj, _JSON_KEY_ASSERT_SCHEME);

                uaf_res_temp->assertion_list = g_list_append(uaf_res_temp->assertion_list, assrt_data);

            }
        }

    }

    g_object_unref(parser);
    _INFO("before _uaf_parser_parse_uaf_response end");
    return uaf_res_temp;

CATCH:
    if (parser != NULL)
        g_object_unref(parser);

    if (uaf_res_temp != NULL)
        _free_response(uaf_res_temp);

    return NULL;
}

static int
__print_string_list(GList *list)
{
    RET_IF_FAIL(list != NULL, -1);

    GList *list_iter = g_list_first(list);
    while (list_iter != NULL) {
        char *data = (char*) (list->data);
        if (data != NULL)
            _INFO("[%s]", data);

        list_iter = list_iter->next;
    }

    return 0;
}

_asm_get_reg_out_t *
_uaf_parser_parser_asm_get_reg_response(const char *get_reg_resp)
{
    _INFO("_uaf_parser_parser_asm_get_reg_response start");

    RET_IF_FAIL(get_reg_resp != NULL, NULL);

    JsonParser *parser = json_parser_new();
    RET_IF_FAIL(parser != NULL, NULL);

    GError *parser_err = NULL;
    gboolean is_parsed = json_parser_load_from_data(parser, get_reg_resp, -1, &parser_err);
    RET_IF_FAIL(is_parsed == TRUE, NULL);

    _INFO("");

    _asm_get_reg_out_t *reg_out = NULL;

    JsonNode *root = json_parser_get_root(parser);
    CATCH_IF_FAIL(root != NULL);

    JsonObject *root_obj = json_node_get_object(root);
    CATCH_IF_FAIL(root_obj != NULL);

    _INFO("");

    /*responseData*/
    JsonObject *res_obj = json_object_get_object_member(root_obj, _JSON_KEY_RESP_DATA);
    CATCH_IF_FAIL(res_obj != NULL);

    /*appRegs*/
    JsonArray *app_reg_json_arr = json_object_get_array_member(res_obj, _JSON_KEY_APP_REGS);
    CATCH_IF_FAIL(app_reg_json_arr != NULL);

    _INFO("");

    int app_reg_json_arr_len = json_array_get_length(app_reg_json_arr);
    CATCH_IF_FAIL(app_reg_json_arr_len > 0);

    reg_out = (_asm_get_reg_out_t*) calloc(1, sizeof(_asm_get_reg_out_t));

    int i = 0;
    for (; i < app_reg_json_arr_len; i++) {
        JsonObject *app_reg_json_obj = json_array_get_object_element(app_reg_json_arr, i);
        if (app_reg_json_obj != NULL) {
            /*appID*/
            const char *app_id = json_object_get_string_member(app_reg_json_obj, _JSON_KEY_APPID);

            _INFO("");

            /*keyIDs*/
            JsonArray *key_id_json_arr = json_object_get_array_member(app_reg_json_obj, _JSON_KEY_KEY_IDS);
            GList *key_id_list = __get_string_list_from_json_array(key_id_json_arr);

            if (app_id != NULL || key_id_list != NULL) {
                _asm_app_reg_t *app_reg = (_asm_app_reg_t*) calloc(1, sizeof(_asm_app_reg_t));

                if (app_id != NULL) {
                    _INFO("app_id = [%s]", app_id);
                    app_reg->app_id = strdup(app_id);
                }

                app_reg->key_id_list = key_id_list;
                __print_string_list(key_id_list);

                reg_out->app_reg_list = g_list_append(reg_out->app_reg_list, app_reg);
                _INFO("");

            }
        }
    }

    _INFO("");
    /*statusCode*/
    reg_out->status_code = __get_int_from_json_object(root_obj, _JSON_KEY_STATUS_CODE);

CATCH:
    g_object_unref(parser);

    _INFO("_uaf_parser_parser_asm_get_reg_response end");
    return reg_out;
}

char *
_uaf_composer_compose_get_registrations_request(const char *auth_index)
{
    _INFO("_uaf_composer_compose_get_registrations_request");

#ifdef WITH_JSON_BUILDER

    JsonBuilder *builder = json_builder_new();

    json_builder_begin_object(builder);

    /*Version : 1.0*/
    json_builder_set_member_name(builder, _JSON_KEY_ASM_VERSION);
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, _JSON_KEY_MAJOR);
    json_builder_add_int_value(builder, _VERSION_MAJOR);
    json_builder_set_member_name(builder, _JSON_KEY_MINOR);
    json_builder_add_int_value(builder, _VERSION_MINOR);
    json_builder_end_object(builder);

    /*authenticatorIndex*/
    json_builder_set_member_name(builder, _JSON_KEY_AUTH_INDEX);
    int auth_index_int = -1;
    sscanf(auth_index, "%d", &auth_index_int);
    json_builder_add_int_value(builder, auth_index_int);


    /*requestType : "GetRegistrations" */
    json_builder_set_member_name(builder, _JSON_KEY_REQ_TYPE);
    json_builder_add_string_value(builder, _JSON_KEY_GET_REGS);


    json_builder_end_object(builder);

    JsonNode *root_builder = json_builder_get_root(builder);
    JsonGenerator *gen = json_generator_new();
    json_generator_set_root(gen, root_builder);

    json_node_free(root_builder);
    g_object_unref(builder);

    gsize len = 0;
    char *json = json_generator_to_data(gen, &len);

    if (json != NULL)
        _INFO("%s", json);

    g_object_unref(gen);
    return json;
 
#else
    JsonGenerator *generator = json_generator_new();
    JsonObject *root_obj = json_object_new();

    if(!__uaf_composer_compose_asm_init(&generator, &root_obj)) {
        dlog_print(DLOG_INFO, "FIDO", "_uaf_composer_compse_asm_init fail");
        goto CATCH;
    }

    /*Version*/
    JsonNode *jsonNode = NULL;
    JsonObject *jsonObject = json_object_new();
    json_object_set_int_member(jsonObject, _JSON_KEY_MAJOR, 1);
    json_object_set_int_member(jsonObject, _JSON_KEY_MINOR, 0);
    json_node_take_object(jsonNode, jsonObject);

    json_object_set_member(root_obj, _JSON_KEY_ASM_VERSION, jsonNode);

    /*authenticatorIndex*/
    int auth_index_int = -1;
    sscanf(auth_index, "%d", &auth_index_int);
    json_object_set_int_member(root_obj, _JSON_KEY_AUTH_INDEX, auth_index_int);

    /*requestType : "GetRegisterations" */
    json_object_set_string_member(root_obj, _JSON_KEY_REQ_TYPE, _JSON_KEY_GET_REGS);

    gsize len = 0;
    char *get_reg_json = json_generator_to_data(generator, &len);

    if(generator != NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    return get_reg_json;

CATCH:
    if(generator != NULL) {
        g_object_unref(generator);
        generator = NULL;
    }

    if(root_obj != NULL) {
        g_object_unref(root_obj);
        root_obj = NULL;
    }

    return NULL;
#endif
}

int
_convert_asm_status_code_to_uaf_error(int asm_status_code)
{
    switch (asm_status_code) {

    case _ASM_STATUS_OK:
        return FIDO_ERROR_NONE;

    case _ASM_STATUS_ERROR:
        return FIDO_ERROR_UNKNOWN;

    case _ASM_STATUS_ACCESS_DENIED:
        return FIDO_ERROR_PERMISSION_DENIED;

    case _ASM_STATUS_USER_CANCELLED:
        return FIDO_ERROR_USER_CANCELLED;

    default:
        return FIDO_ERROR_UNKNOWN;
    }
}

/*
{
    "vendor" : "Samsung Electronics",
    "bin_path" : "/usr/bin/fido-asm",
    "dbus_info" : "org.tizen.fido_uaf_asm.server",
    "dbus_obj_path" : "/org/tizen/fido_uaf_asm/server",
    "dbus_interface_name" : "org.tizen.fido_uaf_asm.server.interface",
    "dbus_method_name" : "asm_request"
}
*/


_fido_asm_proxy_t*
_parse_asm_conf_file(const char *file_name)
{
    _INFO("_parse_asm_conf_file");

    RET_IF_FAIL(file_name != NULL, NULL);

    JsonParser *parser = json_parser_new();

    _fido_asm_proxy_t *proxy = NULL;
    GError *err = NULL;
    gboolean is_parsed = json_parser_load_from_file(parser, file_name, &err);
    CATCH_IF_FAIL(is_parsed == TRUE);

    JsonNode *root = json_parser_get_root(parser);
    CATCH_IF_FAIL(root != NULL);

    JsonObject *root_obj = json_node_get_object(root);
    CATCH_IF_FAIL(root_obj != NULL);

    const char *vendor = json_object_get_string_member(root_obj, _JSON_KEY_VENDOR);
    CATCH_IF_FAIL(vendor != NULL);

    const char *bin_path = json_object_get_string_member(root_obj, _JSON_KEY_BIN_PATH);
    CATCH_IF_FAIL(bin_path != NULL);

    const char *dbus_info = json_object_get_string_member(root_obj, _JSON_KEY_DBUS_INFO);
    CATCH_IF_FAIL(dbus_info != NULL);

    const char *dbus_obj_path = json_object_get_string_member(root_obj, _JSON_KEY_DBUS_OBJ_PATH);
    CATCH_IF_FAIL(dbus_obj_path != NULL);

    const char *dbus_interface_name = json_object_get_string_member(root_obj, _JSON_KEY_DBUS_INTF_NAME);
    CATCH_IF_FAIL(dbus_interface_name != NULL);

    const char *dbus_method_name = json_object_get_string_member(root_obj, _JSON_KEY_DBUS_METHOD_NAME);
    CATCH_IF_FAIL(dbus_method_name != NULL);

    proxy = calloc(1, sizeof(_fido_asm_proxy_t));

    proxy->vendor = strdup(vendor);
    proxy->bin_path = strdup(bin_path);
    proxy->dbus_info = strdup(dbus_info);
    proxy->dbus_obj_path = strdup(dbus_obj_path);
    proxy->dbus_interface_name = strdup(dbus_interface_name);
    proxy->dbus_method_name = strdup(dbus_method_name);

CATCH:
    g_object_unref(parser);
    return proxy;

}
