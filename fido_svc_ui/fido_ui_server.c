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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <glib.h>
#if !GLIB_CHECK_VERSION (2, 31, 0)
#include <glib/gmacros.h>
#endif

#include <app.h>
#include <system_settings.h>
#include <json-glib/json-glib.h>
#include <Elementary.h>
#include <efl_extension.h>
#include <dlog.h>
#include "fido_internal_types.h"
#include "fido_logs.h"

#include "fido-stub.h"
#include "fido_internal_types.h"

#define _FIDO_SERVICE_UI_DBUS_PATH       "/org/tizen/fidosvcui"
#define _FIDO_SERVICE_PATH "/usr/bin/fido-service"

#define _FREEDESKTOP_SERVICE    "org.freedesktop.DBus"
#define _FREEDESKTOP_PATH       "/org/freedesktop/DBus"
#define _FREEDESKTOP_INTERFACE  "org.freedesktop.DBus"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "fidosvcui"

static bool auth_option_selected = FALSE;
static Fido *_fido_dbus_obj = NULL;

typedef struct _ui_data_s {
    char *asm_id;
	char *auth_index;
	char *label;
	int att_t;
} ui_data_s;

typedef struct appdata {
	Evas_Object *win;
	Evas_Object *conform;
	Evas_Object *nf;
	Evas_Object *box;
	Evas_Object *genlist;
	Elm_Genlist_Item_Class* itc;
	Evas_Object *group;
	Evas_Object *radio;
	Evas_Object *btn;
	GList *ui_data_list;
	GDBusMethodInvocation *invocation;
} appdata_s;

static appdata_s *ad = NULL;

static void
__free_ui_data(ui_data_s *data)
{
    RET_IF_FAIL_VOID(data != NULL);

    SAFE_DELETE(data->asm_id);
    SAFE_DELETE(data->auth_index);
    SAFE_DELETE(data->label);

    SAFE_DELETE(data);
}

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

static void
__init_dbus(void)
{
    _INFO("init_dbus");
#if !GLIB_CHECK_VERSION(2,35,0)
    g_type_init();
#endif

    GDBusConnection *connection = NULL;
    GError *error = NULL;

    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);

    _INFO("after g_bus_get_sync");


    /* Create the object */
    _fido_dbus_obj = fido_proxy_new_sync(connection,
                                         G_DBUS_PROXY_FLAGS_NONE,
                                         _FIDO_DBUS_NAME,
                                         _FIDO_DBUS_PATH,
                                         NULL,
                                         &error);
}

static Fido *
__dbus_proxy_get_instance(int time_out)
{
    _INFO("_dbus_proxy_get_instance singleton");

    static pthread_once_t onceBlock = PTHREAD_ONCE_INIT;
    if (_fido_dbus_obj == NULL) {
        pthread_once(&onceBlock, __init_dbus);
        if (_fido_dbus_obj == NULL) {
            _ERR("init_dbus failed");
            onceBlock = PTHREAD_ONCE_INIT;
        }
    }
    _INFO("_dbus_proxy_get_instance end");

    g_dbus_proxy_set_default_timeout(G_DBUS_PROXY(_fido_dbus_obj), time_out);

    return _fido_dbus_obj;
}

static void
__send_response_to_fido_svc(int error, const char *ui_resp)
{
    auth_option_selected = FALSE;

    Fido *dbus_proxy = __dbus_proxy_get_instance(_DBUS_TIMEOUT_USE_DEFAULT);
    if (dbus_proxy == NULL) {
        _ERR("DBus proxy failed");
        return;
    }

    _INFO("Sending to FIDO Service");

    GError *dbus_err = NULL;
    if (ui_resp == NULL)
        fido_call_ui_response_sync(dbus_proxy, FIDO_ERROR_USER_CANCELLED, _EMPTY_JSON_STRING, NULL, &dbus_err);
    else
        fido_call_ui_response_sync(dbus_proxy, error, ui_resp, NULL, &dbus_err);

    if (dbus_err != NULL)
        g_error_free(dbus_err);

    _INFO("UI end");
}

char*
_create_json_response(ui_data_s *selected_auth)
{
	_INFO("_create_json_response");

	/*Builder start*/
	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);

	/*requestType*/
	__add_string_to_json_object(builder, UI_DATA_ASM_ID, selected_auth->asm_id);
	__add_string_to_json_object(builder, UI_DATA_AUTH_INDEX, selected_auth->auth_index);
	__add_string_to_json_object(builder, UI_DATA_LABEL, selected_auth->label);
	__add_int_to_json_object(builder, UI_DATA_ATT_TYPE, selected_auth->att_t);

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

		if (gen != NULL)
			g_object_unref(gen);

		_INFO("%s", json);
		_INFO("_create_json_response end");

		return json;
	}

	g_object_unref(gen);

	_INFO("_create_json_response fail");
	return NULL;
}

void
_list_destroy(gpointer data)
{
	ui_data_s *list_data = (ui_data_s *) data;
	SAFE_DELETE(list_data->auth_index);
	SAFE_DELETE(list_data->label);
}

void
_hide_ui(void)
{
	elm_genlist_clear(ad->genlist);
	g_list_free_full(ad->ui_data_list, (GDestroyNotify) _list_destroy);
	ad->ui_data_list = NULL;
	evas_object_hide(ad->win);
}

void genlist_select_cb(void *data, Evas_Object *obj, void *event_info)
{
	_INFO("genlist_select_cb");

	if (data == NULL) {
		_INFO("data is NULL");
		return;
	}

	if (event_info == NULL) {
		_INFO("event_info is NULL");
		return;
	}

	ui_data_s *selected_auth = (ui_data_s*) data;
	auth_option_selected = TRUE;

	Elm_Object_Item *item = (Elm_Object_Item *) event_info;
	char *sel_txt = (char *) elm_object_item_data_get(item);

	if (!strcmp(sel_txt, selected_auth->label)) {
		char *response = _create_json_response(selected_auth);
		if (response != NULL) {
			_hide_ui();

			_INFO("sending response to ui adaptor");
            __send_response_to_fido_svc(FIDO_ERROR_NONE, response);

            SAFE_DELETE(response);
		}
	}
}

static char*
_item_label_get(void *data, Evas_Object *obj, const char *part)
{
	char buf[256];
	snprintf(buf, sizeof(buf), "%s", (char*) data);
	return strdup(buf);
}

void
_auth_arr_cb(JsonArray *array, guint index, JsonNode *element_node, gpointer user_data)
{
	_INFO("_auth_arr_cb");

	JsonObject *obj = NULL;
	obj = json_node_get_object(element_node);
	if (!obj) {
		_ERR("json_node_get_object() failed");
		return;
	}

	ui_data_s *ui_data = (ui_data_s *) calloc(1, sizeof(ui_data_s));
	if (!ui_data) {
		_ERR("Out of memory");
		return;
	}

    const char *asm_id = json_object_get_string_member(obj, UI_DATA_ASM_ID);
    if (!asm_id) {
        _ERR("json_object_get_string_member() failed");

        __free_ui_data(ui_data);
        return;
    }

	const char *auth_idx = NULL;
	auth_idx = json_object_get_string_member(obj, UI_DATA_AUTH_INDEX);
	if (!auth_idx) {
		_ERR("json_object_get_string_member() failed");

        __free_ui_data(ui_data);
		return;
	}

	const char *label = NULL;
	label = json_object_get_string_member(obj, UI_DATA_LABEL);

	int att = -1;
	att = json_object_get_int_member(obj, UI_DATA_ATT_TYPE);

    ui_data->asm_id = strdup(asm_id);

	ui_data->auth_index = strdup(auth_idx);
    if (label == NULL) {
        ui_data->label = calloc(1, 128);
        snprintf(ui_data->label, 127, "%s", "Unknown Authenticator");
    }
    else
        ui_data->label = strdup(label);

	ui_data->att_t = att;
	ad->ui_data_list = g_list_append(ad->ui_data_list, ui_data);

    _INFO("Adding to ui_data list | auth_index %s | label %s | att_type %d",
                                            auth_idx, ui_data->label, att);

	elm_genlist_item_append(ad->genlist, ad->itc, ui_data->label, NULL,
				ELM_GENLIST_ITEM_NONE, genlist_select_cb, ui_data);

}

static void
_parse_json_ui_in(const char *ui_auth_json)
{
	_INFO("_parse_json_ui_in data %s", ui_auth_json);

	char * ui_auth = strdup(ui_auth_json);
	GError *parse_err = NULL;
	JsonParser *parser = NULL;
	JsonNode *root = NULL;
	JsonArray *auth_data_arr = NULL;

	parser = json_parser_new();
	if (!parser) {
		_ERR("json_parser_new failed");
		goto CATCH;
	}

	json_parser_load_from_data(parser, ui_auth, -1, &parse_err);
	if (parse_err != NULL) {
		_ERR("json parse failure");
		goto CATCH;
	}

	root = json_parser_get_root(parser);
	if (!root) {
		_ERR("json_parser_get_root() failed");
		goto CATCH;
	}

	auth_data_arr = json_node_get_array(root);
	if (!auth_data_arr) {
		_ERR("json_node_get_array() failed");
		goto CATCH;
	}

	/* Genlist Item */
	ad->itc = elm_genlist_item_class_new();
	ad->itc->item_style = "default";
	ad->itc->func.text_get = _item_label_get;
	ad->itc->func.content_get = NULL;
	ad->itc->func.state_get = NULL;

	json_array_foreach_element(auth_data_arr, _auth_arr_cb, NULL);

CATCH:
    if (parser != NULL) {
        g_object_unref(parser);
        parser = NULL;
    }

	if (parse_err != NULL) {
		g_error_free(parse_err);
		parse_err = NULL;
	}

	SAFE_DELETE(ui_auth);

	return;
}

// TODO button callback
/*
static void btn_clicked_cb(void *data, Evas_Object *obj, void *event_info) {

	_INFO("clicked event on Button");

	if (auth_option_selected == TRUE && selected_auth != NULL) {

		char *selected_auth_json = _create_json_response(selected_auth);

		_INFO("sending selected authenticator response");
		fidosvcui_complete_ui_auth_request(ad->object, ad->invocation, 0, selected_auth_json);

	}
}
*/

static void
_win_back_cb(void *data, Evas_Object *obj, void *event_info) 
{
    if (auth_option_selected == FALSE) {
        _ERR("Authenticator not selected by user");
        _hide_ui();
        __send_response_to_fido_svc(FIDO_ERROR_USER_CANCELLED, NULL);
    }
}

static void
_create_ui(void)
{
	_INFO("_create_ui");

	/* Window */
	//ad->win = elm_win_add(NULL, UI_SVC_PACKAGE,  ELM_WIN_BASIC);
    ad->win = elm_win_util_standard_add(_UI_SVC_PACKAGE, "Authenticator Selection UI");
	if (ad->win != NULL)
		_INFO("elm_win_util_standard_add successful");
	else
		_ERR("elm_win_util_standard_add failed");
		
	elm_win_autodel_set(ad->win, EINA_TRUE);

	if (elm_win_wm_rotation_supported_get(ad->win)) {
		int rots[4] = { 0, 90, 180, 270 };
		elm_win_wm_rotation_available_rotations_set(ad->win,
				(const int *) (&rots), 4);
	}

	eext_object_event_callback_add(ad->win, EEXT_CALLBACK_BACK, _win_back_cb, ad);
	evas_object_smart_callback_add(ad->win, "unfocused", _win_back_cb, NULL);

	/* Conformant */
	ad->conform = elm_conformant_add(ad->win);
	elm_win_indicator_mode_set(ad->win, ELM_WIN_INDICATOR_SHOW);
	elm_win_indicator_opacity_set(ad->win, ELM_WIN_INDICATOR_OPAQUE);
	evas_object_size_hint_weight_set(ad->conform, EVAS_HINT_EXPAND,
			EVAS_HINT_EXPAND);
	elm_win_resize_object_add(ad->win, ad->conform);
	evas_object_show(ad->conform);

	/* Naviframe */
	ad->nf = elm_naviframe_add(ad->conform);
	elm_object_content_set(ad->conform, ad->nf);
	evas_object_show(ad->nf);

	/* Box */
	ad->box = elm_box_add(ad->nf);

	/* Genlist */
	ad->genlist = elm_genlist_add(ad->box);
	elm_genlist_homogeneous_set(ad->genlist, EINA_TRUE);

	/* Radio */
	Evas_Object *radio_main = elm_radio_add(ad->genlist);
	elm_radio_state_value_set(radio_main, 0);
	elm_radio_value_set(radio_main, 0);
	evas_object_data_set(ad->genlist, "radio_main", radio_main);

	evas_object_size_hint_weight_set(ad->genlist, EVAS_HINT_EXPAND,
			EVAS_HINT_EXPAND);
	evas_object_size_hint_align_set(ad->genlist, EVAS_HINT_FILL,
			EVAS_HINT_FILL);
	evas_object_show(ad->genlist);
	elm_box_pack_end(ad->box, ad->genlist);

	//~ /* Button */ // TODO check button visibility
	//~ ad->btn = elm_button_add(ad->box);
	//~ elm_object_text_set(ad->btn, "OK");
	//~ evas_object_size_hint_weight_set(ad->btn, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
	//~ evas_object_size_hint_align_set(ad->btn, EVAS_HINT_FILL, EVAS_HINT_FILL);

	//~ Evas_Object *btn_bg = elm_bg_add(ad->btn);
	//~ elm_bg_color_set(btn_bg, 90, 160, 200);

	//~ evas_object_smart_callback_add(ad->btn, "clicked", btn_clicked_cb, ad);
	//~ evas_object_show(ad->btn);
	//~ elm_box_pack_end(ad->box, ad->btn);


	elm_naviframe_item_push(ad->nf, "Select Authenticator",
			NULL, NULL, ad->box, NULL);

	/* Keep window hidden after base gui is set up */
    //evas_object_hide(ad->win);
    
}

static bool
app_create(void *data)
{
    ad = data;
    _create_ui();

    return true;
    }

static void
app_control(app_control_h app_control, void *data)
{
    //_UI_IPC_KEY_REQ
    RET_IF_FAIL_VOID(app_control != NULL);

    char *req_json = NULL;
    app_control_get_extra_data(app_control, _UI_IPC_KEY_REQ, &req_json);
    RET_IF_FAIL_VOID(req_json != NULL);

    _parse_json_ui_in(req_json);

    evas_object_show(ad->win);
}

static void
app_pause(void *data)
{

    }

static void
app_resume(void *data)
{

    }

static void
app_terminate(void *data)
{

}

static void
ui_app_lang_changed(app_event_info_h event_info, void *user_data)
{

    char *locale = NULL;
    system_settings_get_value_string(SYSTEM_SETTINGS_KEY_LOCALE_LANGUAGE, &locale);
    elm_language_set(locale);
    free(locale);
		return;
	}

static void
ui_app_orient_changed(app_event_info_h event_info, void *user_data)
{
		return;
	}

static void
ui_app_region_changed(app_event_info_h event_info, void *user_data)
{
}

static void
ui_app_low_battery(app_event_info_h event_info, void *user_data)
{

	}

static void
ui_app_low_memory(app_event_info_h event_info, void *user_data)
{

}

EXPORT_API int
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
        _INFO("app_main() is failed. err = %d", ret);
    }

    return ret;
}
