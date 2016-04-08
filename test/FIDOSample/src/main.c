/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *		  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include "main.h"
#include "fido.h"
#include <dlog.h>
#include <json-glib/json-glib.h>

#define _REG_REQ_FILE_NAME "/opt/usr/apps/org.tizen.fidosample/res/reg_req.json"
#define _AUTH_REQ_FILE_NAME "/opt/usr/apps/org.tizen.fidosample/res/auth_req.json"
#define _DEREG_REQ_FILE_NAME "/opt/usr/apps/org.tizen.fidosample/res/dereg_req.json"

static char *json_reg = NULL;
static char *json_auth = NULL;
static char *json_dereg = NULL;

static char*
__read(const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    if (file == NULL)
        return NULL;

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    if (size <= 0) {
        fclose(file);
        return NULL;
    }

    fseek(file, 0, SEEK_SET);

    char *json = calloc(1, size + 1);
    int num_bytes = fread(json, size, 1, file);
    if (num_bytes <= 0) {
        free(json);
        fclose(file);
        return NULL;
    }

    json[size] = 0;

    fclose(file);

    return json;

}

static void _response_cb(void *data, Evas_Object *obj, void *event_info)
{
	evas_object_del(data);
}

static void create_popup(char *popup_str, appdata_s *ad)
{
	Evas_Object *popup = elm_popup_add(ad->win);
	Evas_Object *btn;
	char str[2048] = {0,};
	strcpy(str, popup_str);
	elm_popup_align_set(popup, ELM_NOTIFY_ALIGN_FILL, 1.0);
	evas_object_size_hint_weight_set(popup, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
	elm_object_text_set(popup, popup_str);

	btn = elm_button_add(popup);
	elm_object_style_set(btn, "popup");
	evas_object_size_hint_weight_set(btn, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
	elm_object_text_set(btn, "OK");
	elm_object_part_content_set(popup, "button1", btn);
	eext_object_event_callback_add(popup, EEXT_CALLBACK_BACK, eext_popup_back_cb, NULL);
	evas_object_smart_callback_add(btn, "clicked", _response_cb, popup);
	evas_object_show(popup);

	return;
}

char *get_error_code(fido_error_e error_code)
{

	char *error_str = calloc(1, 128);

	if (error_code == FIDO_ERROR_NONE)
		strcpy(error_str, "SUCCESS");
	else if (error_code == FIDO_ERROR_OUT_OF_MEMORY)
		strcpy(error_str, "FIDO_ERROR_OUT_OF_MEMORY");
	else if (error_code == FIDO_ERROR_INVALID_PARAMETER)
		strcpy(error_str, "FIDO_ERROR_INVALID_PARAMETER");
	else if (error_code == FIDO_ERROR_NO_DATA)
		strcpy(error_str, "FIDO_ERROR_NO_DATA");
	else if (error_code == FIDO_ERROR_PERMISSION_DENIED)
		strcpy(error_str, "FIDO_ERROR_PERMISSION_DENIED");
	else if (error_code == FIDO_ERROR_NOT_SUPPORTED)
		strcpy(error_str, "FIDO_ERROR_NOT_SUPPORTED");
	else if (error_code == FIDO_ERROR_USER_ACTION_IN_PROGRESS)
		strcpy(error_str, "FIDO_ERROR_USER_ACTION_IN_PROGRESS");
	else if (error_code == FIDO_ERROR_USER_CANCELLED)
		strcpy(error_str, "FIDO_ERROR_USER_CANCELLED");
	else if (error_code == FIDO_ERROR_UNSUPPORTED_VERSION)
		strcpy(error_str, "FIDO_ERROR_UNSUPPORTED_VERSION");
	else if (error_code == FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR)
		strcpy(error_str, "FIDO_ERROR_NO_SUITABLE_AUTHENTICATOR");
	else if (error_code == FIDO_ERROR_PROTOCOL_ERROR)
		strcpy(error_str, "FIDO_ERROR_PROTOCOL_ERROR");
	else if (error_code == FIDO_ERROR_UNTRUSTED_FACET_ID)
		strcpy(error_str, "FIDO_ERROR_UNTRUSTED_FACET_ID");
	else
		strcpy(error_str, "FIDO_ERROR_UNKNOWN");
	return error_str;
}

void uaf_version_cb(fido_version_h version, void *user_data)
{
	char *str = (char *) user_data;

	char tmp[1024] = {0,};
	int major = -1;
	int minor = -1;

	fido_get_uaf_version(version, &major, &minor);
	if (major != -1) {
		sprintf(tmp, " | Version Major = [%d]", major);
		strcat(str, tmp);
	}

	if (minor != -1) {
		sprintf(tmp, " | Version Minor = [%d]", minor);
		strcat(str, tmp);
	}
}

void fido_attestation_type_cb_list(int att_type, void *user_data)
{
	char *str = (char *) user_data;

	char tmp[1024] = {0,};
	if (att_type != -1) {
		sprintf(tmp, " | Attestation Type = [%d]", att_type);
		strcat(str, tmp);
	}
}

void ext_cb_list(char *ext, void *user_data)
{
	char *str = (char *) user_data;

	char tmp[1024] = {0,};
	if (ext) {
		sprintf(tmp, " | Extension = [%s]", ext);
		strcat(str, tmp);
	}
}

static void
__print_authinfo(fido_authenticator_h auth, appdata_s *ad)
{
	char str[2048] = {0,};
	str[0] = '\0';
	strcpy(str, "DISCOVER RESPONSE");
	char tmp[1024] = {0,};

	char *title =  NULL;
	fido_authenticator_get_title(auth, &title);
	if (title) {
		sprintf(tmp, " | Title = [%s]", title);
		strcat(str, tmp);
	}

	char *aaid = NULL;
	fido_authenticator_get_aaid(auth, &aaid);
	if (aaid) {
		sprintf(tmp, " | AAID = [%s]", aaid);
		strcat(str, tmp);
	}

	char *description = NULL;
	fido_authenticator_get_description(auth, &description);
	if (description) {
		sprintf(tmp, " | Description = [%s]", description);
		strcat(str, tmp);
	}

	char *scheme = NULL;
	fido_authenticator_get_assertion_scheme(auth, &scheme);
	if (scheme) {
		sprintf(tmp, " | Scheme = [%s]", scheme);
		strcat(str, tmp);
	}

	fido_authenticator_foreach_attestation_type(auth, fido_attestation_type_cb_list, str);

	int get_algo = -1;
	fido_authenticator_get_algorithm(auth, &get_algo);
	if (get_algo != -1) {
		sprintf(tmp, " | Algo = [%d]", get_algo);
		strcat(str, tmp);
	}

	int user_ver = -1;
	fido_authenticator_get_verification_method(auth, &user_ver);
	if (user_ver != -1) {
		sprintf(tmp, " | Verification = [%d]", user_ver);
		strcat(str, tmp);
	}

	int key_protection = -1;
	fido_authenticator_get_verification_method(auth, &key_protection);
	if (key_protection != -1) {
		sprintf(tmp, " | Key Protection = [%d]", key_protection);
		strcat(str, tmp);
	}

	int matcher_protection = -1;
	fido_authenticator_get_matcher_protection_method(auth, &matcher_protection);
	if (matcher_protection != -1) {
		sprintf(tmp, " | Matcher Protection = [%d]", matcher_protection);
		strcat(str, tmp);
	}

	int attachment_hint = -1;
	fido_authenticator_get_attachment_hint(auth, &attachment_hint);
	if (attachment_hint != -1) {
		sprintf(tmp, " | Attachment Hint = [%d]", attachment_hint);
		strcat(str, tmp);
	}

	int tc_discplay = -1;
	fido_authenticator_get_tc_discplay(auth, &tc_discplay);
	if (tc_discplay != -1) {
		sprintf(tmp, " | Tc Display = [%d]", tc_discplay);
		strcat(str, tmp);
	}

	char *tc_display_type = NULL;
	fido_authenticator_get_tc_display_type(auth, &tc_display_type);
	if (tc_display_type) {
		sprintf(tmp, " | Tc Display Type = [%s]", tc_display_type);
		strcat(str, tmp);
	}

	char *icon = NULL;
	fido_authenticator_get_icon(auth, &icon);
	if (icon) {
		sprintf(tmp, " | Icon = [%s]", icon);
		strcat(str, tmp);
	}

	fido_uaf_authenticator_foreach_extension(auth, ext_cb_list, str);

	create_popup(str, ad);
}

void auth_list_cb(fido_authenticator_h auth, void *user_data)
{
	appdata_s *ad = user_data;
	__print_authinfo(auth, ad);
}

static void
__print_discovery_data(fido_discovery_data_h discovery_data, appdata_s *ad)
{
	if (discovery_data == NULL)
		return;

	int ret = fido_discovery_data_foreach_authenticator(discovery_data, auth_list_cb, ad);
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_discovery_data_foreach_authenticator =[%d]", ret);

    fido_discovery_data_destroy(discovery_data);
}

static void
_fido_authenticator_cb(int tizen_error_code, fido_discovery_data_h discovery_data, void *user_data)
{
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "discover response = [%d]", tizen_error_code);

	if (tizen_error_code == FIDO_ERROR_NONE) {
		__print_discovery_data(discovery_data, (appdata_s *) user_data);
	} else {
		char *error_string = get_error_code(tizen_error_code);
		create_popup(error_string, (appdata_s *) user_data);
		free(error_string);
	}
}

void
start_discover(void *data, Evas_Object *obj, void *event_info)
{
	int ret = fido_foreach_authenticator(_fido_authenticator_cb, data);
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_foreach_authenticator = [%d]", ret);
}

static void
_policy_cb(int tizen_error_code, void *user_data)
{
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "_policy_cbresponse = [%d]", tizen_error_code);
	char str[2048] = {0,};
	str[0] = '\0';

	strcpy(str, "CHECK POLICY RESPONSE | ");
	char *error_string = get_error_code(tizen_error_code);

	sprintf(str, "ret = [%s]", error_string);
	create_popup(str, (appdata_s *) user_data);
	free(error_string);
}

void
start_check_policy(void *data, Evas_Object *obj, void *event_info)
{
	int ret = fido_request_is_supported(json_reg, _policy_cb, data);
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_foreach_authenticator = [%d]", ret);
}

static void
_process_cb(int tizen_error_code, char *uaf_response, void *user_data)
{
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "process response = [%d]", tizen_error_code);
	char str[2048] = {0,};
	if (tizen_error_code == 0) {
		dlog_print(DLOG_INFO, "org.tizen.Fidosample", "uaf response = %s", uaf_response);

		strcat(str, "uaf response = ");
		strcat(str, uaf_response);
		create_popup(str, (appdata_s *) user_data);
	} else {
		char *error_string = get_error_code(tizen_error_code);
		create_popup(error_string, (appdata_s *) user_data);
		free(error_string);
	}
}

void
start_registration(void *data, Evas_Object *obj, void *event_info)
{
	if (json_reg != NULL) {
		int ret = fido_request_get_registration_response(json_reg, NULL, _process_cb, data);
		dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_request_get_registration_response = [%d]", ret);

		char str[2048] = {0,};
		str[0] = '\0';
		strcpy(str, "REGISTRATION RESPONSE | ");
		char tmp[1024] = {0,};
		sprintf(tmp, "ret = [%d] | ", ret);
		strcat(str, tmp);
	}
}

void
start_auth(void *data, Evas_Object *obj, void *event_info)
{
	if (json_auth != NULL) {
		int ret = fido_request_get_authentication_response(json_auth, NULL, _process_cb, data);
		dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_request_get_authentication_response = [%d]", ret);

		char str[2048] = {0,};
		str[0] = '\0';
		strcpy(str, "AUTHENTICATION RESPONSE | ");
		char tmp[1024] = {0,};
		sprintf(tmp, "ret = [%d] | ", ret);
		strcat(str, tmp);
	}
}

static void
_process_dereg_cb(int tizen_error_code, char *uaf_response, void *user_data)
{
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "process response = [%d]", tizen_error_code);

	char *error_string = get_error_code(tizen_error_code);
	create_popup(error_string, (appdata_s *) user_data);
	free(error_string);
}

void
start_de_registration(void *data, Evas_Object *obj, void *event_info)
{
	if (json_reg != NULL) {
		int ret = fido_request_get_deregistration_response(json_dereg, NULL, _process_dereg_cb, data);
		dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_request_get_deregistration_response = [%d]", ret);

		char str[2048] = {0,};
		str[0] = '\0';
		strcpy(str, "DE-REGISTRATION RESPONSE | ");
		char tmp[1024] = {0,};
		sprintf(tmp, "ret = [%d] | ", ret);
		strcat(str, tmp);
	}
}

static void
_process_cb_for_notify_pos(int tizen_error_code, char *uaf_response, void *user_data)
{
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "process response = [%d]", tizen_error_code);

	if (tizen_error_code == 0) {
		dlog_print(DLOG_INFO, "org.tizen.Fidosample", "uaf response = %s", uaf_response);

		int ret = fido_request_set_result(FIDO_SERVER_STATUS_CODE_OK, uaf_response);
        dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_request_set_result =[%d]", ret);

		char *error_string = get_error_code(tizen_error_code);
		create_popup(error_string, (appdata_s *) user_data);
		free(error_string);
	} else {
		char *error_string = get_error_code(tizen_error_code);
		create_popup(error_string, (appdata_s *) user_data);
		free(error_string);
	}
}

static void
_process_cb_for_notify_neg(int tizen_error_code, char *uaf_response, void *user_data)
{
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "process response = [%d]", tizen_error_code);

	if (tizen_error_code == 0) {
		dlog_print(DLOG_INFO, "org.tizen.Fidosample", "uaf response = %s", uaf_response);

		int ret = fido_request_set_result(0, uaf_response);
        dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_request_set_result =[%d]", ret);

		char *error_string = get_error_code(tizen_error_code);
		create_popup(error_string, (appdata_s *) user_data);
		free(error_string);
	} else {
		char *error_string = get_error_code(tizen_error_code);
		create_popup(error_string, (appdata_s *) user_data);
		free(error_string);
	}
}

void
start_notify_pos(void *data, Evas_Object *obj, void *event_info)
{
	if (json_reg != NULL) {
		int ret = fido_request_get_registration_response(json_reg, NULL, _process_cb_for_notify_pos, data);
		dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_request_get_registration_response = [%d]", ret);
	}
}

void
start_notify_neg(void *data, Evas_Object *obj, void *event_info)
{
	if (json_reg != NULL) {
		int ret = fido_request_get_registration_response(json_reg, NULL, _process_cb_for_notify_neg, data);
		dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_request_get_registration_response = [%d]", ret);
	}
}

static void
win_delete_request_cb(void *data, Evas_Object *obj, void *event_info)
{
	/* To make your application go to background,
		Call the elm_win_lower() instead
		Evas_Object *win = (Evas_Object *) data;
		elm_win_lower(win); */
	ui_app_exit();
}

static void
list_selected_cb(void *data, Evas_Object *obj, void *event_info)
{
	Elm_Object_Item *it = event_info;
	elm_list_item_selected_set(it, EINA_FALSE);
}

static Eina_Bool
naviframe_pop_cb(void *data, Elm_Object_Item *it)
{
	ui_app_exit();
	return EINA_FALSE;
}

static void
create_list_view(appdata_s *ad)
{
	Evas_Object *list;
	Evas_Object *btn;
	Evas_Object *nf = ad->nf;
	Elm_Object_Item *nf_it;

	/* List */
	list = elm_list_add(nf);
	elm_list_mode_set(list, ELM_LIST_COMPRESS);
	evas_object_smart_callback_add(list, "selected", list_selected_cb, NULL);

	/* Main Menu Items Here */
	elm_list_item_append(list, "Discover", NULL, NULL, start_discover, ad);
	elm_list_item_append(list, "Check Policy", NULL, NULL, start_check_policy, ad);
	elm_list_item_append(list, "Registration", NULL, NULL, start_registration, ad);
	elm_list_item_append(list, "Authentication", NULL, NULL, start_auth, ad);
	elm_list_item_append(list, "De-Registration", NULL, NULL, start_de_registration, ad);
	elm_list_item_append(list, "NotifyResult with Success", NULL, NULL, start_notify_pos, ad);
	elm_list_item_append(list, "NotifyResult with Failure", NULL, NULL, start_notify_neg, ad);

	elm_list_go(list);

	/* This button is set for devices which doesn't have H/W back key. */
	btn = elm_button_add(nf);
	elm_object_style_set(btn, "naviframe/end_btn/default");
	nf_it = elm_naviframe_item_push(nf, "FIDO Test App", btn, NULL, list, NULL);
	elm_naviframe_item_pop_cb_set(nf_it, naviframe_pop_cb, ad->win);
}

static void
create_base_gui(appdata_s *ad)
{
	/*
	 * Widget Tree
	 * Window
	 *  - conform
	 *   - layout main
	 *    - naviframe */

	/* Window */
	ad->win = elm_win_util_standard_add(PACKAGE, PACKAGE);
	elm_win_conformant_set(ad->win, EINA_TRUE);
	elm_win_autodel_set(ad->win, EINA_TRUE);

	if (elm_win_wm_rotation_supported_get(ad->win)) {
		int rots[4] = { 0, 90, 180, 270 };
		elm_win_wm_rotation_available_rotations_set(ad->win, (const int *)(&rots), 4);
	}

	evas_object_smart_callback_add(ad->win, "delete,request", win_delete_request_cb, NULL);

	/* Conformant */
	ad->conform = elm_conformant_add(ad->win);
	evas_object_size_hint_weight_set(ad->conform, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
	elm_win_resize_object_add(ad->win, ad->conform);
	evas_object_show(ad->conform);

	/* Indicator */
	/* elm_win_indicator_mode_set(ad->win, ELM_WIN_INDICATOR_SHOW); */

	/* Base Layout */
	ad->layout = elm_layout_add(ad->conform);
	evas_object_size_hint_weight_set(ad->layout, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
	elm_layout_theme_set(ad->layout, "layout", "application", "default");
	evas_object_show(ad->layout);

	elm_object_content_set(ad->conform, ad->layout);

	/* Naviframe */
	ad->nf = elm_naviframe_add(ad->layout);
	create_list_view(ad);
	elm_object_part_content_set(ad->layout, "elm.swallow.content", ad->nf);
	eext_object_event_callback_add(ad->nf, EEXT_CALLBACK_BACK, eext_naviframe_back_cb, NULL);
	eext_object_event_callback_add(ad->nf, EEXT_CALLBACK_MORE, eext_naviframe_more_cb, NULL);

	/* Show window after base gui is set up */
	evas_object_show(ad->win);
}

static bool
app_create(void *data)
{
	/* Hook to take necessary actions before main event loop starts
	   Initialize UI resources and application's data
	   If this function returns true, the main loop of application starts
	   If this function returns false, the application is terminated */
	appdata_s *ad = data;

	elm_app_base_scale_set(1.8);
	create_base_gui(ad);

	int ret = fido_uaf_init();
	dlog_print(DLOG_INFO, "org.tizen.Fidosample", "fido_uaf_init = [%d]", ret);

	json_reg = __read(_REG_REQ_FILE_NAME);
	json_auth = __read(_AUTH_REQ_FILE_NAME);
	json_dereg = __read(_DEREG_REQ_FILE_NAME);

	return true;
}

static void
app_control(app_control_h app_control, void *data)
{
	/* Handle the launch request. */
}

static void
app_pause(void *data)
{
	/* Take necessary actions when application becomes invisible. */
}

static void
app_resume(void *data)
{
	/* Take necessary actions when application becomes visible. */
}

static void
app_terminate(void *data)
{
	/* Release all resources. */
}

static void
ui_app_lang_changed(app_event_info_h event_info, void *user_data)
{
	/*APP_EVENT_LANGUAGE_CHANGED*/
	char *locale = NULL;
	system_settings_get_value_string(SYSTEM_SETTINGS_KEY_LOCALE_LANGUAGE, &locale);
	elm_language_set(locale);
	free(locale);
	return;
}

static void
ui_app_orient_changed(app_event_info_h event_info, void *user_data)
{
	/*APP_EVENT_DEVICE_ORIENTATION_CHANGED*/
	return;
}

static void
ui_app_region_changed(app_event_info_h event_info, void *user_data)
{
	/*APP_EVENT_REGION_FORMAT_CHANGED*/
}

static void
ui_app_low_battery(app_event_info_h event_info, void *user_data)
{
	/*APP_EVENT_LOW_BATTERY*/
}

static void
ui_app_low_memory(app_event_info_h event_info, void *user_data)
{
	/*APP_EVENT_LOW_MEMORY*/
}

int
main(int argc, char *argv[])
{
	appdata_s ad = {0,};
	int ret = 0;

	ui_app_lifecycle_callback_s event_callback = {0,};
	app_event_handler_h handlers[5] = {NULL, };

	event_callback.create = app_create;
	event_callback.terminate = app_terminate;
	event_callback.pause = app_pause;
	event_callback.resume = app_resume;
	event_callback.app_control = app_control;

	ui_app_add_event_handler(&handlers[APP_EVENT_LOW_BATTERY], APP_EVENT_LOW_BATTERY, ui_app_low_battery, &ad);
	ui_app_add_event_handler(&handlers[APP_EVENT_LOW_MEMORY], APP_EVENT_LOW_MEMORY, ui_app_low_memory, &ad);
	ui_app_add_event_handler(&handlers[APP_EVENT_DEVICE_ORIENTATION_CHANGED], APP_EVENT_DEVICE_ORIENTATION_CHANGED, ui_app_orient_changed, &ad);
	ui_app_add_event_handler(&handlers[APP_EVENT_LANGUAGE_CHANGED], APP_EVENT_LANGUAGE_CHANGED, ui_app_lang_changed, &ad);
	ui_app_add_event_handler(&handlers[APP_EVENT_REGION_FORMAT_CHANGED], APP_EVENT_REGION_FORMAT_CHANGED, ui_app_region_changed, &ad);
	ui_app_remove_event_handler(handlers[APP_EVENT_LOW_MEMORY]);

	ret = ui_app_main(argc, argv, &event_callback, &ad);
	if (ret != APP_ERROR_NONE) {
		dlog_print(DLOG_ERROR, LOG_TAG, "app_main() is failed. err = %d", ret);
	}

	return ret;
}
