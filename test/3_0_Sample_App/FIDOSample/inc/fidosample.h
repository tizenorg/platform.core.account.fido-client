#ifndef __fidosample_H__
#define __fidosample_H__

#include <stdio.h>
#include <app.h>
#include <Elementary.h>
#include <system_settings.h>
#include <dlog.h>
#include <efl_extension.h>

#ifdef  LOG_TAG
#undef  LOG_TAG
#endif
#define LOG_TAG "fidosample"

#if !defined(PACKAGE)
#define PACKAGE "org.example.fidosample"
#endif

typedef struct appdata {
	Evas_Object *win;
	Evas_Object *conform;
	Evas_Object *layout;
	Evas_Object *nf;
	Evas_Object *datetime;
	Evas_Object *popup;
	Evas_Object *button;
	struct tm saved_time;
} appdata_s;

void start_discover(void *data, Evas_Object *obj, void *event_info);
void start_check_policy(void *data, Evas_Object *obj, void *event_info);
void start_registration(void *data, Evas_Object *obj, void *event_info);
void start_auth(void *data, Evas_Object *obj, void *event_info);
void start_de_registration(void *data, Evas_Object *obj, void *event_info);

#endif /* __fidosample_H__ */
