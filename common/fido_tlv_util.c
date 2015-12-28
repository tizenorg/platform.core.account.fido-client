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

#include <tizen.h>
#include <glib.h>
#include <stdlib.h>
#include "fido_internal_types.h"
#include "fido_logs.h"
#include "fido_keys.h"
#include "fido_b64_util.h"
#include "fido_tlv_util.h"

static _tlv_t*
__get_tlv_pack_by_type(const guchar *tlv_buffer_in, uint16_t type_in, int max_len_in)
{
    //_INFO("__get_tlv_pack_by_type [%u]", type_in);

    int i = 0;

    while (1) {
        uint16_t lb = tlv_buffer_in[i + 0];
        uint16_t  hb = tlv_buffer_in[i + 1];

        uint16_t val = hb << 8;
        val = val | lb;

        uint16_t type = val;

        lb = 0;
        hb = 0;
        val = 0;

        lb = tlv_buffer_in[i + 2];
        hb = tlv_buffer_in[i + 3];

        val = hb << 8;
        val = val | lb;

        uint16_t length = val;

        if (type == type_in) {
            _tlv_t *tlv = (_tlv_t*)calloc(1, sizeof(_tlv_t));
            tlv->type = type;
            tlv->len = length;
            if (tlv->len > 0) {
                tlv->val = (uint8_t *)calloc(1, tlv->len);
                memcpy(tlv->val, tlv_buffer_in + i + 2 + 2, tlv->len);
            }
            //_INFO("Found key");
            return tlv;
        }

        i += 2 + 2 + length;
        if (i >= max_len_in)
            break;
    }

    return NULL;
}


_auth_reg_assertion_tlv_t*
_tlv_util_decode_reg_assertion(char *tlv_enc)
{
    _INFO("_tlv_util_decode_reg_assertion");

    RET_IF_FAIL(tlv_enc != NULL, NULL);

    _INFO("%s", tlv_enc);

    int in_len = strlen(tlv_enc);
    int tlv_dec_len = in_len * 1.5;
    unsigned char *tlv_dec = calloc(1, tlv_dec_len);

    int r = _fido_b64url_decode((unsigned char *)tlv_enc, in_len, tlv_dec, &tlv_dec_len);
	RET_IF_FAIL(r == 0, NULL);

    _INFO("in len = [%d], decoded len = [%d]", in_len, tlv_dec_len);

    _tlv_t *reg_tlv = __get_tlv_pack_by_type(tlv_dec, TAG_UAFV1_REG_ASSERTION, tlv_dec_len);
    if (reg_tlv != NULL) {
        _INFO("Found TAG_UAFV1_REG_ASSERTION");

        _free_tlv(reg_tlv);

        int krd_start_idx = 2 + 2;

        _tlv_t *krd_tlv = __get_tlv_pack_by_type(tlv_dec + krd_start_idx, TAG_UAFV1_KRD, (tlv_dec_len - krd_start_idx));
        if (krd_tlv != NULL) {
            _INFO("Found TAG_UAFV1_KRD");
            _free_tlv(krd_tlv);

            int krd_inner_start_idx = krd_start_idx + 2 + 2;

            _tlv_t *aaid_tlv = __get_tlv_pack_by_type(tlv_dec + krd_inner_start_idx, TAG_AAID, (tlv_dec_len - krd_inner_start_idx));

            _tlv_t *key_id_tlv = __get_tlv_pack_by_type(tlv_dec + krd_inner_start_idx, TAG_KEYID, (tlv_dec_len - krd_inner_start_idx));


            _auth_reg_assertion_tlv_t *assrt_tlv = (_auth_reg_assertion_tlv_t*)calloc(1, sizeof(_auth_reg_assertion_tlv_t));

            if (aaid_tlv != NULL) {
                _INFO("Found TAG_AAID");

                assrt_tlv->aaid = (char*)calloc(1, aaid_tlv->len + 1);
                memcpy(assrt_tlv->aaid, aaid_tlv->val, aaid_tlv->len);

                _free_tlv(aaid_tlv);
            }

            if (key_id_tlv != NULL) {
                _INFO("Found TAG_KEYID");

                assrt_tlv->key_id = (unsigned char*)calloc(1, key_id_tlv->len);
                memcpy(assrt_tlv->key_id, key_id_tlv->val, key_id_tlv->len);

                assrt_tlv->key_id_len = key_id_tlv->len;

                _INFO("key_id len = [%d]", key_id_tlv->len);

                _free_tlv(key_id_tlv);
            }

            _INFO("Found TAG_KEYID");
            return assrt_tlv;
        }
    }


    return NULL;
}

