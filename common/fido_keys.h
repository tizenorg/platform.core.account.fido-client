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

#ifndef FIDO_KEYS_H
#define FIDO_KEYS_H

#include <tizen.h>

typedef enum {
    _USER_VER_METHOD_MIN = -1,
    _USER_VER_METHOD_PRESENCE = 0X01,
    _USER_VER_METHOD_FINGERPRINT = 0X02,
    _USER_VER_METHOD_PASSCODE = 0X04,
    _USER_VER_METHOD_VOICE_PRINT = 0X08,
    _USER_VER_METHOD_FACE_PRINT = 0X10,
    _USER_VER_METHOD_LOCATION = 0X20,
    _USER_VER_METHOD_EYE_PRINT = 0X40,
    _USER_VER_METHOD_PATTERN = 0X80,
    _USER_VER_METHOD_HAND_PRINT = 0X100,
    _USER_VER_METHOD_NONE = 0X200,
    _USER_VER_METHOD_ALL = 0X400,
    _USER_VER_METHOD_MAX
} _user_verification_method_e;

#define _UAF_OPERATION_NAME_KEY_REG "Reg"

#define _UAF_OPERATION_NAME_KEY_AUTH "Auth"

#define _UAF_OPERATION_NAME_KEY_DE_REG "Dereg"

#define TAG_UAFV1_REG_ASSERTION 0x3E01

#define TAG_UAFV1_AUTH_ASSERTION 0x3E02

#define TAG_UAFV1_KRD 0x3E03

#define TAG_UAFV1_SIGNED_DATA 0x3E04

#define TAG_ATTESTATION_CERT 0x2E05

#define TAG_SIGNATURE 0x2E06

#define TAG_ATTESTATION_BASIC_FULL 0x3E07

#define TAG_ATTESTATION_BASIC_SURROGATE 0x3E08

#define TAG_KEYID 0x2E09

#define TAG_FINAL_CHALLENGE 0x2E0A

#define TAG_AAID 0x2E0B

#define TAG_PUB_KEY 0x2E0C

#define TAG_COUNTERS 0x2E0D

#define TAG_ASSERTION_INFO 0x2E0E

#define TAG_AUTHENTICATOR_NONCE 0x2E0F

#define TAG_TRANSACTION_CONTENT_HASH 0x2E10

#define TAG_EXTENSION 0x3E11, 0x3E12

#define TAG_EXTENSION_ID 0x2E13

#define TAG_EXTENSION_DATA 0x2E14

#endif // FIDO_KEYS_H
