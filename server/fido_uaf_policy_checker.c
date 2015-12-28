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

#include "fido_keys.h"
#include "fido_logs.h"
#include "fido_uaf_policy_checker.h"
#include "fido_json_handler.h"

//static _fido_asm_proxy_t*
//__dup_asm_proxy(const _fido_asm_proxy_t *src)
//{
//    _fido_asm_proxy_t *dest = calloc(1, sizeof(_fido_asm_proxy_t));
//    dest->bin_path = strdup(src->bin_path);
//    dest->dbus_info = strdup(src->dbus_info);
//    dest->dbus_interface_name = strdup(src->dbus_interface_name);
//    dest->dbus_method_name = strdup(src->dbus_method_name);
//    dest->dbus_obj_path = strdup(src->dbus_obj_path);
//    dest->vendor = strdup(src->vendor);

//    dest->dbus_proxy = src->dbus_proxy;

//    return dest;
//}

static gint
_int_cmp(gconstpointer a, gconstpointer b)
{
    int int1 = GPOINTER_TO_INT(a);
    int int2 = GPOINTER_TO_INT(b);
    return (int1 - int2);
}

bool
_policy_checker_is_matched(_match_criteria_t *match_criteria, fido_authenticator_s *auth_info)
{
    _INFO("_policy_checker_is_matched");

    /* -1 means the int value is not present, so we should ignore that. */

    /* 1. If any AAID is mentioned in match_criteria, then atleast one AAID should match */
    GList *aaid_list = match_criteria->aaid_list;

    if (aaid_list &&
            (g_list_length(aaid_list)) &&
            (auth_info->aaid) &&
            (strlen(auth_info->aaid) > 0)) {
        aaid_list = g_list_first(aaid_list);
        if (g_list_find_custom(aaid_list, auth_info->aaid, (GCompareFunc)strcmp) == NULL) {
            _ERR("AAID match failed");
            return false;
        }
    }


    /* 2. If any Vendor ID is mentioned in match_criteria, then atleast one Vendor ID should match */
    GList *vendor_list = match_criteria->vendor_list;

    if (vendor_list && auth_info->aaid) {
        char *auth_aaid = strdup(auth_info->aaid);
        char *auth_vendor = strtok(auth_aaid, "#");

        if (vendor_list &&
                (g_list_length(vendor_list)) &&
                auth_vendor &&
                (strlen(auth_vendor) > 0)) {
            vendor_list = g_list_first(vendor_list);
            if (g_list_find_custom(vendor_list, auth_vendor, (GCompareFunc)strcmp) == NULL) {
                _ERR("Vendor ID match failed");

                SAFE_DELETE(auth_aaid);
                return false;
            }
        }
        SAFE_DELETE(auth_aaid);
    }

    _INFO("keyid matching");

    /* 3. If any Key ID is mentioned in match_criteria, then atleast one Key ID should match */
    GList *key_id_list = match_criteria->key_id_list;

    if (key_id_list != NULL) {

        if (auth_info->key_ids == NULL) {
            _ERR("keyID match failed");
            return false;
        }

        GList *auth_key_ids = auth_info->key_ids;

        GList *common_key_id_list = NULL;

        key_id_list = g_list_first(key_id_list);
        auth_key_ids = g_list_first(auth_key_ids);

        _INFO("match_criteria keyid count = [%d]", g_list_length(key_id_list));
        _INFO("auth info keyid count = [%d]", g_list_length(auth_key_ids));

        GList *key_id_iter = g_list_first(key_id_list);
        while (key_id_iter != NULL) {
            char *key_id = (char*) (key_id_iter->data);
            if (key_id) {
                if (g_list_find_custom(auth_key_ids, key_id, (GCompareFunc)strcmp) != NULL) {
                    _INFO("keyid matched [%s]", key_id);
                    common_key_id_list = g_list_append(common_key_id_list, strdup(key_id));
                }
            }
            key_id_iter = key_id_iter->next;
        }

        if (common_key_id_list == NULL) {
            _ERR("keyID match failed");
            return false;
        }

        common_key_id_list = g_list_first(common_key_id_list);

        /*Set common keyIds in match*/
        g_list_free_full(match_criteria->key_id_list, free);
        match_criteria->key_id_list = common_key_id_list;

        _INFO("keyID matched count [%d]", g_list_length(match_criteria->key_id_list));

    }

    _INFO("User verification matching");

    /* 4. User verification match */
    if (match_criteria->user_verification != -1) {
        if ((match_criteria->user_verification == auth_info->user_verification)
                ||
                (
                        ((auth_info->user_verification & _USER_VER_METHOD_ALL) == 0)
                        &&
                        ((match_criteria->user_verification & _USER_VER_METHOD_ALL) == 0)
                        &&
                        ((auth_info->user_verification & match_criteria->user_verification) != 0)
                )
        )
            _INFO("User verification match passed");
        else {
            _ERR("User verification match failed");
            return false;
        }
    }

    /* 5. Key protection field bit matching */
    if ((match_criteria->key_protection != -1) && auth_info->key_protection) {
        if (((match_criteria->key_protection) && (auth_info->key_protection)) == 0) {
            _ERR("Key protection match failed");
            return false;
        }
    }

    /* 6. Matcher Protection field bit matching */
    if ((match_criteria->matcher_protection != -1) && auth_info->matcher_protection) {
        if (((match_criteria->matcher_protection) && (auth_info->matcher_protection)) == 0) {
            _ERR("Matcher protection match failed");
            return false;
        }
    }

    /* 7. Attachment hint field bit matching */
    if ((match_criteria->attachement_hint != -1) && auth_info->attachment_hint) {
        if (((match_criteria->attachement_hint) && (auth_info->attachment_hint)) == 0) {
            _ERR("Attachment hint match failed");
            return false;
        }
    }

    /* 8. TC Display field bit matching */
    if ((match_criteria->tc_display != -1) && auth_info->tc_display) {
        if (((match_criteria->tc_display) && (auth_info->tc_display)) == 0) {
            _ERR("Attachment hint match failed");
            return false;
        }
    }

    /* 9. If any algo is mentioned in match_criteria, then atleast one algo should match */
    GList *match_algo_list = match_criteria->auth_algo_list;
    if (match_algo_list && (g_list_length(match_algo_list))
            && (auth_info->authentication_algorithm)) {
        match_algo_list = g_list_first(match_algo_list);
        if (g_list_find_custom(match_algo_list, GINT_TO_POINTER(auth_info->authentication_algorithm), (GCompareFunc)_int_cmp) == NULL) {
            _ERR("Algorithm match failed");
            return false;
        }
    }

    /* 10. If any assertion scheme is mentioned in match_criteria, then atleast one assertion scheme should match */
    GList *assertion_list = match_criteria->assertion_scheme_list;
    if (assertion_list && (g_list_length(assertion_list))
            && (auth_info->assertion_scheme) && (strlen(auth_info->assertion_scheme) > 0)) {
        assertion_list = g_list_first(assertion_list);
        if (g_list_find_custom(assertion_list, auth_info->assertion_scheme, (GCompareFunc)strcmp) == NULL)
        {
            _ERR("Assertion scheme match failed");
            return false;
        }
    }

    /* 11. If any attestation type is mentioned in match_criteria, then atleast one attestation type should match */
    GList *attestation_type_list = match_criteria->attestation_type_list;
    if (attestation_type_list && (g_list_length(attestation_type_list))
            && (auth_info->attestation_types)) {
        attestation_type_list = g_list_first(attestation_type_list);
        if (g_list_find_custom(attestation_type_list, GINT_TO_POINTER(auth_info->attestation_types), (GCompareFunc)_int_cmp) == NULL) {
            _ERR("Attestation type match failed");
            return false;
        }
    }

    /* TODO : 12. Auth version */

    /* TODO : 13. Extension */

    _INFO("_policy_checker_is_matched true");

    return true;
}

int
_get_attestation_type(_match_criteria_t *match_criteria, fido_authenticator_s *auth_info)
{
     _INFO("_get_attestation_type");

    if (match_criteria && match_criteria->attestation_type_list) {

        GList *match_att_list_iter = g_list_first(match_criteria->attestation_type_list);
        while (match_att_list_iter != NULL) {

            int match_att_type = GPOINTER_TO_INT(match_att_list_iter->data);

            if (auth_info && auth_info->attestation_types) {

                GList *auth_att_list_iter = g_list_first(auth_info->attestation_types);
                while (auth_att_list_iter != NULL) {

                    int auth_att_type = GPOINTER_TO_INT(auth_att_list_iter->data);

                    if (match_att_type == auth_att_type) {
                        _INFO("_get_attestation_type end [%d]", match_att_type);
                        return match_att_type;
                    }
                }
            }
            match_att_list_iter = match_att_list_iter->data;
        }
    }
    else {
        if (auth_info->attestation_types != NULL) {
            GList *att_type_iter = g_list_first(auth_info->attestation_types);

            /*Returning first attestation type in case policy does not mandate any*/
            while (att_type_iter != NULL) {
                int auth_att_type = GPOINTER_TO_INT(att_type_iter->data);
                _INFO("Returning first attestation type in case policy does not mandate any [%d]", auth_att_type);
                return auth_att_type;
            }
        }
    }

    _ERR("_get_attestation_type end");
    return -1;
}

static char *
__get_verification_method_string(unsigned long int ver_method)
{
    char *ver_str = calloc(1, 128);

    switch (ver_method) {

    case _USER_VER_METHOD_PRESENCE:
        snprintf(ver_str, 127, "%s", "Presence Authenticator");
        break;

    case _USER_VER_METHOD_FINGERPRINT:
        snprintf(ver_str, 127, "%s", "Fingerprint Authenticator");
        break;

    case _USER_VER_METHOD_PASSCODE:
        snprintf(ver_str, 127, "%s", "Passcode Authenticator");
        break;

    case _USER_VER_METHOD_VOICE_PRINT:
        snprintf(ver_str, 127, "%s", "Voice Print Authenticator");
        break;

    case _USER_VER_METHOD_FACE_PRINT:
        snprintf(ver_str, 127, "%s", "Face Print Authenticator");
        break;

    case _USER_VER_METHOD_LOCATION:
        snprintf(ver_str, 127, "%s", "Location Authenticator");
        break;

    case _USER_VER_METHOD_EYE_PRINT:
        snprintf(ver_str, 127, "%s", "Eye Print Authenticator");
        break;

    case _USER_VER_METHOD_PATTERN:
        snprintf(ver_str, 127, "%s", "Pattern Authenticator");
        break;

    case _USER_VER_METHOD_HAND_PRINT:
        snprintf(ver_str, 127, "%s", "Hand Print Authenticator");
        break;

//    case _USER_VER_METHOD_NONE:
//        snprintf(ver_str, "%s", "");
//        break;

    case _USER_VER_METHOD_ALL:
        snprintf(ver_str, 127, "%s", "All Authenticator");
        break;

    default:
        snprintf(ver_str, 127, "%s", "Other Type");
        break;
    }

    return ver_str;
}

static GList*
__copy_string_list(GList *src)
{
    RET_IF_FAIL(src != NULL, NULL);

    GList *dest = NULL;

    GList *iter = g_list_first(src);
    while (iter != NULL) {
        char *str = (char*)(iter->data);
        dest = g_list_append(dest, strdup(str));

        iter = iter->next;
    }

    return dest;
}

/* Returns _matched_auth_data_t list*/
GList *
_policy_checker_get_matched_auth_list(_policy_t *policy, GList *auth_list)
{
    _INFO("_policy_checker_get_matched_auth_list");

    if (policy == NULL)
        _INFO("policy is NULL");

    if (auth_list == NULL)
        _INFO("auth_list is NULL");

    RET_IF_FAIL(policy != NULL, NULL);
    RET_IF_FAIL(auth_list != NULL, NULL);

    //    _match_criteria_t *match_criteria_or = NULL;
    GList *allowed_list = NULL;
    GList *disallowed_list = policy->disallowed_list;
    GList *accepted_list = policy->accepted_list;

    if (accepted_list != NULL)
        _INFO("accepted_list count = [%d]", g_list_length(accepted_list));

    if (disallowed_list != NULL)
        _INFO("allowed_list count = [%d]", g_list_length(disallowed_list));

    GList *accepted_list_iter = g_list_first(accepted_list);
    while (accepted_list_iter != NULL) {

        GList *accepted_list_internal = (GList *) accepted_list_iter->data;
        GList *accepted_list_internal_iter = g_list_first(accepted_list_internal);
        while (accepted_list_internal_iter != NULL) {
            _match_criteria_t *match_info = (_match_criteria_t *) accepted_list_internal_iter->data;

            GList *auth_list_iter = g_list_first(auth_list);
            while (auth_list_iter != NULL) {
                fido_authenticator_s *authenticator = (fido_authenticator_s*) (auth_list_iter->data);

                if (_policy_checker_is_matched(match_info, authenticator)) {
                    _INFO("[%s] is matched from allowed list", authenticator->aaid);

                    /*Disallowed list can be NULL, which means put all which are matching with accepted list*/

                    if (disallowed_list != NULL) {

                        GList *disallowed_list_iter = g_list_first(disallowed_list);
                        while (disallowed_list_iter != NULL) {
                            _match_criteria_t *disallowed_match_info = (_match_criteria_t *) disallowed_list_iter->data;

                            if (!_policy_checker_is_matched(disallowed_match_info, authenticator)) {
                                _INFO("[%s] is not in disallowed list", authenticator->aaid);
                                _matched_auth_data_t *matched_auth_data = (_matched_auth_data_t*) calloc(1, sizeof(_matched_auth_data_t));
                                RET_IF_FAIL(matched_auth_data, NULL);

                                /*TODO : ASM must send auth index*/
                                if (authenticator->auth_index != NULL)
                                    matched_auth_data->auth_index = strdup(authenticator->auth_index);
                                else
                                    _ERR("auth index missing");

                                matched_auth_data->att_type = _get_attestation_type(match_info, authenticator);

                                if (authenticator->title != NULL)
                                    matched_auth_data->label = strdup(authenticator->title);
                                else {
                                    _ERR("title missing, putting ver method");
                                    /*If label is null, set verification method name instead*/
                                    matched_auth_data->label = __get_verification_method_string(authenticator->user_verification);
                                }


                                if (authenticator->asm_id != NULL)
                                    matched_auth_data->asm_id = strdup(authenticator->asm_id);
                                else
                                    _ERR("Authenticator does not have any ASM ID!!");

                                matched_auth_data->key_ids = __copy_string_list(match_info->key_id_list);

                                allowed_list = g_list_append(allowed_list, matched_auth_data);
                            }
                            disallowed_list_iter = disallowed_list_iter->next;
                        }
                    }
                    else {
                        _INFO("[%s] adding since no disallowed list", authenticator->aaid);
                        _matched_auth_data_t *matched_auth_data = (_matched_auth_data_t*) calloc(1, sizeof(_matched_auth_data_t));
                        RET_IF_FAIL(matched_auth_data, NULL);

                        matched_auth_data->auth_index = strdup(authenticator->auth_index);
                        matched_auth_data->att_type = _get_attestation_type(match_info, authenticator);
                        if (authenticator->title != NULL)
                            matched_auth_data->label = strdup(authenticator->title);
                        else {
                            _ERR("title missing, putting ver method");
                            /*If label is null, set verification method name instead*/
                            matched_auth_data->label = __get_verification_method_string(authenticator->user_verification);
                        }

                        if (authenticator->asm_id != NULL)
                            matched_auth_data->asm_id = strdup(authenticator->asm_id);
                        else
                            _ERR("Authenticator does not have any ASM ID!!");

                        matched_auth_data->key_ids = __copy_string_list(match_info->key_id_list);

                        allowed_list = g_list_append(allowed_list, matched_auth_data);
                    }
                }
                auth_list_iter = auth_list_iter->next;
            }
            accepted_list_internal_iter = accepted_list_internal_iter->next;
        }
        accepted_list_iter = accepted_list_iter->next;
    }

    if (allowed_list != NULL)
        allowed_list = g_list_first(allowed_list);

    return allowed_list;
}

/* Returns _matched_auth_dereg_t list */
GList*
_policy_checker_get_matched_auth_list_dereg(const char *app_id, GList *input_auth_list, GList *available_auth_list)
{
	_INFO("");

	RET_IF_FAIL(app_id, NULL);
    RET_IF_FAIL(input_auth_list, NULL);
    RET_IF_FAIL(available_auth_list, NULL);

	_INFO("");

    GList *matched_auth_dereg_list = NULL;

    GList *input_auth_list_iter = g_list_first(input_auth_list);
    while (input_auth_list_iter != NULL) {
        _dereg_auth_info_t *dereg_auth_info = (_dereg_auth_info_t*) (input_auth_list_iter->data);

        GList *available_auth_list_iter = g_list_first(available_auth_list);
        while (available_auth_list_iter != NULL) {
            fido_authenticator_s *authenticator = (fido_authenticator_s*) (available_auth_list_iter->data);

			if (dereg_auth_info->aaid != NULL)
				_INFO("Input AAID = [%s]", dereg_auth_info->aaid);

			if (authenticator->aaid != NULL)
				_INFO("Authenticator AAID = [%s]", authenticator->aaid);
			
            if (dereg_auth_info->aaid && authenticator->aaid && !strcmp(dereg_auth_info->aaid, authenticator->aaid)) {
                _matched_auth_dereg_t *matched_auth_dereg = (_matched_auth_dereg_t*) calloc(1, sizeof(_matched_auth_dereg_t));
                RET_IF_FAIL(matched_auth_dereg, NULL);

                matched_auth_dereg->auth_index = strdup(authenticator->auth_index);
                matched_auth_dereg->app_id = strdup(app_id);
                matched_auth_dereg->key_id = strdup(dereg_auth_info->key_id);
                if (authenticator->asm_id != NULL)
                    matched_auth_dereg->asm_id = strdup(authenticator->asm_id);
                else
                    _ERR("Authenticator does not have any ASM ID!!");

				_INFO("");
                matched_auth_dereg_list = g_list_append(matched_auth_dereg_list, matched_auth_dereg);
            }
            available_auth_list_iter = available_auth_list_iter->next;
        }
        input_auth_list_iter = input_auth_list_iter->next;
    }

    return matched_auth_dereg_list;
}
