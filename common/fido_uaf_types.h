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

#ifndef FIDO_UAF_TYPES_H_
#define FIDO_UAF_TYPES_H_

#include <tizen.h>
#include <stdint.h>

/**
 * @addtogroup CAPI_FIDO_MODULE
 * @{
 */

/**
 * @file fido_uaf_types.h
 * @brief The FIDO UAF Client API enums and typedefs.
 */

/**
 * @brief  The structure type for the Authenticator handle.
 * @since_tizen  3.0
 */
typedef struct fido_authenticator_s* fido_authenticator_h;

#define TIZEN_ERROR_FIDO        -0x01030000

/**
 *  @brief    Enumerations of error codes for FIDO APIs.
 *  @since_tizen 3.0
 */
typedef enum
{
    FIDO_ERROR_NONE                  = TIZEN_ERROR_NONE,                   /**< Successful. */
    FIDO_ERROR_OUT_OF_MEMORY             = TIZEN_ERROR_OUT_OF_MEMORY,              /**< Out of memory. */
    FIDO_ERROR_INVALID_PARAMETER         = TIZEN_ERROR_INVALID_PARAMETER,        /**< Invalid parameter. */
    FIDO_ERROR_NO_DATA  = TIZEN_ERROR_NO_DATA, /**< Empty data. */
    FIDO_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED, /**< Permission Denied. */

    FIDO_ERROR_NOT_SUPPORTED = TIZEN_ERROR_NOT_SUPPORTED, /**< FIDO is unsupported. */
    FIDO_ERROR_USER_ACTION_IN_PROGRESS = TIZEN_ERROR_FIDO | 0x01, /**< User action is in progress. */
    FIDO_ERROR_USER_CANCELLED = TIZEN_ERROR_FIDO | 0x02, /**< User has canceled the operation. */
    FIDO_ERROR_UNSUPPORTED_VERSION = TIZEN_ERROR_FIDO | 0x03, /**< UAF message's version is not supported. */
    FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR = TIZEN_ERROR_FIDO | 0x04, /**< No suitable authenticators found. */
    FIDO_ERROR_PROTOCOL_ERROR = TIZEN_ERROR_FIDO | 0x05, /**< Protocol error, the interaction may have timed out, or
                                                              the UAF message is malformed. */
    FIDO_ERROR_UNTRUSTED_FACET_ID = TIZEN_ERROR_FIDO | 0x06, /**< The caller's id is not allowed to use this operation. */
    FIDO_ERROR_UNKNOWN = TIZEN_ERROR_UNKNOWN /**< Unknown system error.*/

} fido_error_e;

/**
 *  @brief  Authenticator's supported algorithm and encoding.
 *  @remarks Refer to FIDO UAF Registry document for more details.
 *  @since_tizen 3.0
 */
typedef enum
{
	FIDO_AUTH_ALGO_SECP256R1_ECDSA_SHA256_RAW = 0X01, /**< SECP256R1 ECDSA SHA256 Raw */
	FIDO_AUTH_ALGO_SECP256R1_ECDSA_SHA256_DER = 0X02, /**< SECP256R1 ECDSA SHA256 DER*/
	FIDO_AUTH_ALGO_RSASSA_PSS_SHA256_RAW = 0x03, /**< RSA PSS SHA256 Raw*/
	FIDO_AUTH_ALGO_RSASSA_PSS_SHA256_DER = 0x04, /**< RSA PSS SHA256 DER*/
	FIDO_AUTH_ALGO_SECP256K1_ECDSA_SHA256_RAW = 0x05, /**< SECP256K1 ECDSA SHA256 Raw*/
	FIDO_AUTH_ALGO_SECP256K1_ECDSA_SHA256_DER = 0x06 /**< SECP256K1 ECDSA SHA256 DER*/
} fido_auth_algo_e;

/**
 *  @brief  Authenticator's supported Attestation type.
 *  @remarks Refer to FIDO UAF Registry document for more details.
 *  @since_tizen 3.0
 */
typedef enum
{
	FIDO_AUTH_ATT_TYPE_BASIC_FULL = 0x3E07, /**< Full basic attestation. */
	FIDO_AUTH_ATT_TYPE_BASIC_SURROGATE = 0x3E08 /**< Surrogate basic attestation. */
} fido_auth_attestation_type_e;

/**
 *  @brief  Authenticator's supported user verification method type.
 *  @remarks Refer to FIDO UAF Registry document for more details.
 *  @since_tizen 3.0
 */
typedef enum
{
	FIDO_AUTH_USR_VERIFY_TYPE_PRESENCE = 0x01, /**< User presence verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_FINGERPRINT = 0x02, /**< User fingerprint verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_PASSCODE = 0x04, /**< User passcode verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_VOICEPRINT = 0x08, /**< User voiceprint verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_FACEPRINT = 0x10, /**< User faceprint verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_LOCATION = 0x20, /**< User location verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_EYEPRINT = 0x40, /**< User eyeprint verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_PATTERN = 0x80, /**< User pattern verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_HANDPRINT = 0x100, /**< User handprint verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_NONE = 0x200, /**< Silent verification. */
	FIDO_AUTH_USR_VERIFY_TYPE_ALL =  0x400 /**< If an authenticator sets multiple flags for user verification types,
											* it may also set this flag to indicate that all verification methods will be enforced
											* (e.g. faceprint AND voiceprint). If flags for multiple user verification methods are set
											* and this flag is not set, verification with only one is necessary
											* (e.g. fingerprint OR passcode).
											*/
} fido_auth_user_verify_type_e;

/**
 *  @brief  Authenticator's supported key protection method type.
 *  @remarks Refer to FIDO UAF Registry document for more details.
 *  @since_tizen 3.0
 */
typedef enum
{
	FIDO_AUTH_KEY_PROT_TYPE_SOFTWARE = 0x01, /**< Software based key management. */
	FIDO_AUTH_KEY_PROT_TYPE_HARDWARE = 0x02, /**< Hardware based key management. */
	FIDO_AUTH_KEY_PROT_TYPE_TEE = 0x04, /**< Trusted Execution Environment based key management. */
	FIDO_AUTH_KEY_PROT_TYPE_SECURE_ELEMENT = 0x08, /**< Secure Element based key management. */
	FIDO_AUTH_KEY_PROT_TYPE_REMOTE_HANDLE  = 0x10 /**< Authenticator does not store (wrapped) UAuth keys at the client,
												   * but relies on a server-provided key handle.
												   */
} fido_auth_key_protection_type_e;

/**
 *  @brief  Authenticator's supported matcher protection type.
 *  @remarks Refer to FIDO UAF Registry document for more details.
 *  @since_tizen 3.0
 */
typedef enum
{
	FIDO_AUTH_MATCH_PROT_TYPE_SOFTWARE = 0x01, /**< Authenticator's matcher is running in software. */
	FIDO_AUTH_MATCH_PROT_TYPE_TEE = 0x02, /**< Authenticator's matcher is running inside the Trusted Execution Environment. */
	FIDO_AUTH_MATCH_PROT_TYPE_ON_CHIP  = 0x04 /**< Aauthenticator's matcher is running on the chip. */
} fido_auth_matcher_protection_type_e;

/**
 *  @brief  Authenticator's supproted method to communicate to FIDO user device.
 *  @remarks Refer to FIDO UAF Registry document for more details.
 *  @since_tizen 3.0
 */
typedef enum
{
	FIDO_AUTH_ATTACH_HINT_INTERNAL = 0x01, /**< Authenticator is permanently attached to the FIDO User Device. */
	FIDO_AUTH_ATTACH_HINT_EXTERNAL = 0x02, /**< Authenticator is removable or remote from the FIDO User Device. */
	FIDO_AUTH_ATTACH_HINT_WIRED = 0x04, /**< The external authenticator currently has an exclusive wired connection. */
	FIDO_AUTH_ATTACH_HINT_WIRELESS = 0x08, /**< The external authenticator communicates with the FIDO User Device through
											* wireless means. */
	FIDO_AUTH_ATTACH_HINT_NFC = 0x10, /**< Authenticator is able to communicate by NFC to the FIDO User Device. */
	FIDO_AUTH_ATTACH_HINT_BT = 0x20, /**< Authenticator is able to communicate by Bluetooth to the FIDO User Device. */
	FIDO_AUTH_ATTACH_HINT_NW = 0x40, /**< Authenticator is connected to the FIDO User Device ver a non-exclusive network
									  * (e.g. over a TCP/IP LAN or WAN, as opposed to a PAN or point-to-point connection).
									  */
	FIDO_AUTH_ATTACH_HINT_READY = 0x80, /**< The external authenticator is in a "ready" state. */
	FIDO_AUTH_ATTACH_HINT_WIFI_DIRECT = 0x100 /**< The external authenticator is able to
											   * communicate using WiFi Direct with the FIDO User Device.
											   */
} fido_auth_attachment_hint_e;

/**
 *  @brief  Transaction confirmation display capability type.
 *  @remarks Refer to FIDO UAF Registry document for more details.
 *  @since_tizen 3.0
 */
typedef enum
{
	FIDO_AUTH_TC_DISP_TYPE_ANY = 0x01, /**< Some form of transaction confirmation display is available on this authenticator. */
	FIDO_AUTH_TC_DISP_TYPE_PRIVILEGED_SOFTWARE = 0x02, /**< Software-based transaction confirmation display operating in a
														* privileged context is available on this authenticator.
														*/
	FIDO_AUTH_TC_DISP_TYPE_TEE = 0x04, /**< Transaction confirmation display is in a Trusted Execution Environment. */
	FIDO_AUTH_TC_DISP_TYPE_HW = 0x08, /**< Transaction confirmation display based on hardware assisted capabilities is available on this authenticator.*/
	FIDO_AUTH_TC_DISP_TYPE_REMOTE = 0x10 /**< Transaction confirmation display is provided on a distinct device from the FIDO User Device. */
} fido_auth_tc_display_type_e;


/**
 * @brief  The FIDO Server response for successfull interaction.
 * @since_tizen  3.0
 */
#define FIDO_SERVER_STATUS_CODE_OK 1200

/**
 * @}
 */

#endif /* FIDO_UAF_TYPES_H_ */
