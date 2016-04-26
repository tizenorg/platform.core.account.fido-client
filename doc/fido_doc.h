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

#ifndef __FIDO_DOC_H__
#define __FIDO_DOC_H__

/**
 * @defgroup  CAPI_FIDO_MODULE FIDO Client
 * @ingroup   CAPI_ACCOUNT_FRAMEWORK
 * @brief     The FIDO Client APIs provide Fast IDentity Online UAF Client specification APIs.
 *
 * @section   CAPI_FIDO_HEADER Required Header
 *  \#include <fido.h>
 *
  * @section CAPI_FIDO_MODULE_OVERVIEW Overview
 * The FIDO Universal Authentication Framework (UAF) Client APIs provide APIs for application developers to utilize Device's available authenticators for online service integration.
 * The goal of this Universal Authentication Framework is to provide a unified and extensible authentication mechanism that supplants passwords while avoiding the shortcomings of current alternative authentication approaches.
 * More details about the FIDO specification can be found in https://fidoalliance.org/specifications/download/
  * @section CAPI_FIDO_MODULE_FEATURE Related Features
 * This API is related with the following feature:\n
 * - http://tizen.org/feature/fido.uaf
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 * @defgroup  CAPI_FIDO_UAF_MESSAGES_MODULE FIDO UAF MESSAGES
 * @ingroup   CAPI_FIDO_MODULE
 * @brief     Fido UAF Messasges
 *
 * @section   CAPI_FIDO_UAF_CLIENT_HEADER Required Header
 *  \#include <fido_uaf_client.h>
 *
 * @section CAPI_FIDO_REQUESTS_MODULE_OVERVIEW Overview
 * The FIDO UAF Client APIs which process UAF meesages from fido server.
 * More details about the FIDO specification can be found in https://fidoalliance.org/specifications/download
 *
 * @defgroup  CAPI_FIDO_AUTHENTICATOR_MODULE FIDO AUTHENTICATOR
 * @ingroup   CAPI_FIDO_MODULE
 * @brief     Fido Authenticator
 *
 * @section   CAPI_FIDO_UAF_AUTHENTICATOR_HEADER Required Header
 *  \#include <fido_uaf_authenticator.h>
 *
 * @section CAPI_FIDO_AUTHENTICATOR_MODULE_OVERVIEW Overview
 * Authenticator information, received in response of fido_foreach_authenticator() call, via fido_authenticator_cb() callback.
 * More details about the FIDO specification can be found in https://fidoalliance.org/specifications/download/
*/

#endif /* __FIDO_DOC_H__  */
