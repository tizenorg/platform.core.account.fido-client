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

#ifndef FIDO_JSON_PARSER_H_
#define FIDO_JSON_PARSER_H_

#include <tizen.h>
#include <glib.h>
#include "fido_uaf_types.h"
#include "fido_internal_types.h"

_message_t *_uaf_parser_parse_message(const char *uaf_json, const gchar *channel_binding);

/*List of fido_authenticator_s */
GList* _uaf_parser_parse_asm_response_discover(GList *asm_response_list, int *error_code);
GList* _uaf_parser_parse_asm_response_discover_client(char **asm_response_list, int len, int *error_code);

_asm_out_t *_uaf_parser_parse_asm_response_reg(const char *asm_response_json, int *error_code);

_asm_out_t *_uaf_parser_parse_asm_response_auth(const char *asm_response_json, int *error_code);

_asm_dereg_out_t *_uaf_parser_parse_asm_response_dereg(const char *asm_response_json, int *error_code);

GList *_uaf_parser_parse_trusted_facets(const char *json);

_response_t *_uaf_parser_parse_uaf_response(const char *uaf_response);

_asm_get_reg_out_t *_uaf_parser_parser_asm_get_reg_response(const char *get_reg_resp);

int _uaf_composer_compose_asm_reg_request(_version_t *version, int auth_index, _fido_asm_reg_in_t *reg_in, char **asm_reg_json);

int _uaf_composer_compose_asm_auth_request(_version_t *version, int auth_index, _fido_asm_auth_in_t *auth_in, char **asm_auth_json);

int _uaf_composer_compose_asm_dereg_request(_version_t *version, int auth_index, _matched_auth_dereg_t *dereg_in, char **asm_dereg_json);

char* _uaf_composer_compose_final_challenge(const char *app_id, const char *challenge, const char *facet_id, const char *ch_bin);

int _uaf_composer_compose_uaf_process_response_reg(_op_header_t *header, char *final_ch, GList *assertions, char **uaf_response);

int _uaf_composer_compose_uaf_process_response_auth(_op_header_t *header, char *final_ch, GList *assertions, char **uaf_response);

char *_uaf_composer_compose_dereg_request(_response_t *uaf_res);

char *_uaf_composer_compose_get_registrations_request(const char *auth_index);

int _convert_asm_status_code_to_uaf_error(int asm_status_code);

_fido_asm_proxy_t* _parse_asm_conf_file(const char *file_name);


#endif /* FIDO_JSON_PARSER_H_ */
