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

#ifndef _FIDO_UAF_AUTH_H_
#define _FIDO_UAF_AUTH_H_

#include "fido_uaf_types.h"

/**
 * @file fido_uaf_authenticator.h
 * @brief Authenticator information, received in response of fido_foreach_authenticator() call,
 * via fido_authenticator_cb() callback.
 */

/**
 * @addtogroup CAPI_FIDO_AUTHENTICATOR_MODULE
 * @{
 */

/**
 * @brief Called once for each result of calling fido_foreach_authenticator()
 * @since_tizen 3.0
 *
 * @param[out] auth_info The Authenticator info handle. This param will be freed by framework.
 * @param[out] user_data The user data that was attached during fido_foreach_authenticator() call.
 * @see fido_foreach_authenticator()
 */
typedef void (
  *fido_authenticator_cb) (
  const fido_authenticator_h auth_info,
  void *user_data);

/**
 * @brief Retrieves  all the available FIDO authenticators supported by this Device.
 * @details fido_authenticator_cb() callback is called synchronously once for each authenticator.
 * @since_tizen 3.0
 *
 *
 * @param[in] cb The iteration callback handle.
 * @param[in] user_data The user data handle.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_OUT_OF_MEMORY      Out of Memory
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval     #FIDO_ERROR_PERMISSION_DENIED The application does not have permission to call this API.
 * @retval     #FIDO_ERROR_NOT_SUPPORTED FIDO is not supported on this device.
 */
EXPORT_API int fido_foreach_authenticator (
  fido_authenticator_cb cb,
  void *user_data);

/**
 * @brief Gets the Authenticator title.
 * @since_tizen 3.0
 *
 * @remarks		The application must free title using free().
 * @param[in] auth The Authenticator handle.
 * @param[out] title The title.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_OUT_OF_MEMORY      Out of Memory
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_title (
  const fido_authenticator_h auth,
  char **title);

/**
 * @brief Retrieves the Authenticator AAID(Authenticator Attestation ID).
 * @since_tizen 3.0
 *
 * @remarks		The application must free aaid using free().
 * @param[in] auth The Authenticator handle.
 * @param[out] aaid The AAID.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_OUT_OF_MEMORY      Out of Memory
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_aaid (
  const fido_authenticator_h auth,
  char **aaid);

/**
 * @brief Retrieves the Authenticator description
 * @since_tizen 3.0
 *
 * @remarks		The application must free desc using free().
 * @param[in] auth The Authenticator handle.
 * @param[out] desc The description.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_OUT_OF_MEMORY      Out of Memory
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_description (
  const fido_authenticator_h auth,
  char **desc);

/**
 * @brief Retrieves the Authenticator assertion scheme.
 * @since_tizen 3.0
 *
 * @remarks		The application must free scheme using free().Refer to FIDO UAF Registry document for more details.
 * @param[in] auth The Authenticator handle.
 * @param[out] scheme The assertion scheme. UAFV1TLV is the default assertion scheme.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_OUT_OF_MEMORY      Out of Memory
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_assertion_scheme (
  const fido_authenticator_h auth,
  char **scheme);

/**
 * @brief Retrieves the Authenticator algorithm
 * @since_tizen 3.0
 *
 * @param[in] auth The Authenticator handle.
 * @param[out] algo The authenitcation algorithm.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_algorithm (
  const fido_authenticator_h auth,
  fido_auth_algo_e * algo);

/**
 * @brief Called once for each result of calling fido_authenticator_foreach_attestation_type()
 * @since_tizen 3.0
 *
 * @param[out] att_type The Authenticator attestation type.
 * @param[out] user_data The user data that was attached during fido_authenticator_foreach_attestation_type() call.
 */
typedef void (
  *fido_attestation_type_cb) (
  fido_auth_attestation_type_e att_type,
  void *user_data);

/**
 * @brief Retrieves all the available attestation types for this Authenticator.
 * @since_tizen 3.0
 *
 * @param[in] auth The Authenticator handle.
 * @param[in] cb The iteration callback.
 * @param[in] user_data The user data.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_foreach_attestation_type (
  const fido_authenticator_h auth,
  fido_attestation_type_cb cb,
  void *user_data);

/**
 * @brief Retrieves the user verification method of this Authenticator.
 * @since_tizen 3.0
 *
 * @param[in] auth The Authenticator handle.
 * @param[out] user_verification The user verification method.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_verification_method (
  const fido_authenticator_h auth,
  fido_auth_user_verify_type_e * user_verification);

/**
 * @brief Retrieves the key protection method of this Authenticator.
 * @since_tizen 3.0
 *
 * @param[in] auth The Authenticator handle.
 * @param[out] key_protection The key protection method.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_APIint fido_authenticator_get_key_protection_method (
  const fido_authenticator_h auth,
  fido_auth_key_protection_type_e * key_protection);

/**
 * @brief Retrieves the matcher protection method of this Authenticator.
 * @since_tizen 3.0
 *
 * @param[in] auth The Authenticator handle.
 * @param[out] matcher_protection The matcher protection method.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_matcher_protection_method (
  const fido_authenticator_h auth,
  fido_auth_matcher_protection_type_e * matcher_protection);

/**
 * @brief Retrieves the attachment hint of this Authenticator.
 * @since_tizen 3.0
 *
 * @param[in] auth The Authenticator handle.
 * @param[out] attachment_hint The matcher protection method.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_attachment_hint (
  const fido_authenticator_h auth,
  fido_auth_attachment_hint_e * attachment_hint);

/**
 * @brief Checks if the Authenticator is Second factor only which is supported by U2F standards.
 * @since_tizen 3.0
 *
 * @param[in] auth The Authenticator handle.
 *
 * @return     @c true if its only second factor,
 *             otherwise false.
 */
EXPORT_API bool fido_authenticator_get_is_second_factor_only (
  const fido_authenticator_h auth);

/**
 * @brief Retrieves the Transaction Confirmation display type of this Authenticator.
 * @since_tizen 3.0
 *
 * @param[in] auth The Authenticator handle.
 * @param[out] tc_display The TC display type.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_tc_discplay (
  const fido_authenticator_h auth,
  fido_auth_tc_display_type_e * tc_display);

/**
 * @brief Retrieves the Transaction Confirmation display content type of this Authenticator.
 * @since_tizen 3.0
 *
 * @remarks		The application must free tc_display_content_type using free().
 * @param[in] auth The Authenticator handle.
 * @param[out] tc_display_content_type The TC display content type which is supported MIME type [RFC2049] such as text/plain or image/png.
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_OUT_OF_MEMORY      Out of Memory
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_tc_display_type (
  const fido_authenticator_h auth,
  char **tc_display_content_type);

/**
 * @brief Retrieves the icon of this Authenticator.
 * @since_tizen 3.0
 *
 * @remarks		The application must free icon using free().
 * @param[in] auth The Authenticator handle.
 * @param[out] icon The icon. Portable Network Graphic (PNG) format image file representing the icon encoded as a data: url[RFC2397].
 *
 * @return     @c 0 on success,
 *             otherwise a negative error value
 * @retval     #FIDO_ERROR_NONE               Successful
 * @retval     #FIDO_ERROR_OUT_OF_MEMORY      Out of Memory
 * @retval     #FIDO_ERROR_INVALID_PARAMETER  Invalid parameter
 */
EXPORT_API int fido_authenticator_get_icon (
  const fido_authenticator_h auth,
  char **icon);

/**
 * @}
 */

#endif
