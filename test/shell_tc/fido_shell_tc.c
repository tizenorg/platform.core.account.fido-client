
#include "fido_shell_tc_util.h"
#include "fido.h"

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

static char *json_reg = "[ { \"header\": { \"upv\": { \"major\": 1, \"minor\": 0 },\"op\":\"Reg\", \"serverData\": \"nwV8EPqS5raZdAgH3GD9Z-ytCA9MkiiWaCsr1GHHNJ2yUh3HaV1HHxd4Z67FefJOD5sQYZvipfg5BavhdWPMecD2SH39aJixoXN9ZaNwRlcftJe9WbtPNDC9q5V9WX7Z5jCwkAwehcI\" }, \"challenge\": \"9pIcUwwrY5eD9o3OwfhkeHLnoIl0vaeJUbxSHMe_XgE\", \"username\":\"ryan\", \"policy\": { \"accepted\": [ [ { \"aaid\": [ \"0001#8001\" ] } ], [ { \"aaid\": [ \"DDDD#F001\" ] } ] ] } } ]";
static char *json_auth = "[ { \"header\": { \"upv\": { \"major\": 1, \"minor\": 0 }, \"op\": \"Auth\", \"serverData\": \"emKubKMS8RxYOth7J8enT_x7dQWBaO1CiC0fGmSEhX56kq2RYo1LRpwvfHlzYRI3p9Ay-l4zJcV3lX6rQ0CYNWi5nNDabClFm3k0pPj0kX5V-db9ejN_05y2J6wqztSD\" }, \"challenge\": \"1AM2yZY4-9SG4Ns7-hMdB8IV_FTDKFFiUqNJNVbsVoo\", \"transaction\": [ { \"contentType\": \"text/plain\", \"content\": \"VHJhbnNhY3Rpb24gQ29udGVudCBmb3IgVGVzdC4\", \"tcDisplayPNGCharacteristics\": [ { \"width\": 320, \"height\": 240, \"bitDepth\": 16, \"colorType\": 2, \"compression\": 0, \"filter\": 0, \"interlace\": 0 } ] } ], \"policy\": { \"accepted\": [ [ { \"aaid\": [ \"0001#8001\" ] } ], [ { \"aaid\": [ \"DDDD#F001\" ] } ] ] } } ]";
static char *json_dereg = "[ { \"header\": { \"upv\": { \"major\": \"1\", \"minor\": \"0\" }, \"op\": \"Dereg\" }, \"authenticators\": [ { \"aaid\": \"0001#8001\", \"keyID\": \"uWrbo_8JI1HmPESrNAStTVV8ZbBrzLsf_kZu1QKX2YY\" } ] } ]";

void get_user_choice(void);

static char *
__get_error_code(fido_error_e error_code)
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

static void
__show_error(int tizen_error_code)
{
	char *error_string = __get_error_code(tizen_error_code);
	printf("%s\n", error_string);
	fflush(stdout);
	free(error_string);
}

static void
__process_cb(fido_error_e tizen_error_code, const char *uaf_response, void *user_data)
{
	if (tizen_error_code == 0 && uaf_response != NULL) {

		const int max_str_len = strlen(uaf_response) + 500;
		char *display_str = calloc(1, max_str_len);

		snprintf(display_str, max_str_len - 1, "UAF Response =%s", uaf_response);

		printf("%s\n", uaf_response);
		free(display_str);
	} else {
		__show_error(tizen_error_code);
	}
	get_user_choice();
}

#define STRING_SIZE_1024 1024
#define STRING_SIZE_5000 5000

void fido_attestation_type_cb_list(fido_auth_attestation_type_e att_type, void *user_data)
{
	char *str = (char *) user_data;

	char tmp[STRING_SIZE_1024] = {0,};
	if (att_type != -1) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Attestation Type = [%d]", att_type);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}
}

static char *
__get_authinfo_string(const fido_authenticator_h auth)
{
	char str[STRING_SIZE_5000] = {0,};
	str[0] = '\0';
	strcpy(str, "DISCOVER RESPONSE");
	char tmp[STRING_SIZE_1024] = {0,};

	char *title =  NULL;
	fido_authenticator_get_title(auth, &title);
	if (title) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Title = [%s]", title);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}
	free(title);

	char *aaid = NULL;
	fido_authenticator_get_aaid(auth, &aaid);
	if (aaid) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | AAID = [%s]", aaid);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}
	free(aaid);

	char *description = NULL;
	fido_authenticator_get_description(auth, &description);
	if (description) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Description = [%s]", description);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}
	free(description);

	char *scheme = NULL;
	fido_authenticator_get_assertion_scheme(auth, &scheme);
	if (scheme) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Scheme = [%s]", scheme);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}
	free(scheme);

	fido_authenticator_foreach_attestation_type(auth, fido_attestation_type_cb_list, str);

	fido_auth_algo_e get_algo = -1;
	fido_authenticator_get_algorithm(auth, &get_algo);
	if (get_algo != -1) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Algo = [%d]", get_algo);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}

	fido_auth_user_verify_type_e user_ver = -1;
	fido_authenticator_get_verification_method(auth, &user_ver);
	if (user_ver != -1) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Verification = [%d]", user_ver);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}

	fido_auth_key_protection_type_e key_protection = -1;
	fido_authenticator_get_key_protection_method(auth, &key_protection);
	if (key_protection != -1) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Key Protection = [%d]", key_protection);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}

	fido_auth_matcher_protection_type_e matcher_protection = -1;
	fido_authenticator_get_matcher_protection_method(auth, &matcher_protection);
	if (matcher_protection != -1) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Matcher Protection = [%d]", matcher_protection);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}

	fido_auth_attachment_hint_e attachment_hint = -1;
	fido_authenticator_get_attachment_hint(auth, &attachment_hint);
	if (attachment_hint != -1) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Attachment Hint = [%d]", attachment_hint);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}

	fido_auth_tc_display_type_e tc_discplay = -1;
	fido_authenticator_get_tc_discplay(auth, &tc_discplay);
	if (tc_discplay != -1) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Tc Display = [%d]", tc_discplay);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}

	char *tc_display_type = NULL;
	fido_authenticator_get_tc_display_type(auth, &tc_display_type);
	if (tc_display_type) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Tc Display Type = [%s]", tc_display_type);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}
	free(tc_display_type);

	char *icon = NULL;
	fido_authenticator_get_icon(auth, &icon);
	if (icon) {
		snprintf(tmp, STRING_SIZE_1024 - 1, " | Icon = [%s]", icon);
		strncat(str, tmp, STRING_SIZE_1024 - 1);
	}
	free(icon);

	return strdup(str);
}

static void
auth_list_cb(const fido_authenticator_h auth, void *user_data)
{
	char *auth_info_str = __get_authinfo_string(auth);
	if (auth_info_str != NULL)
		printf("%s", auth_info_str);

}

void
find_auth(void)
{
	int ret = fido_foreach_authenticator(auth_list_cb, NULL);

	if (ret != FIDO_ERROR_NONE) {
		__show_error(ret);
	}
	get_user_choice();
}

void
check_supported(void)
{
	bool is_supported = false;
	int ret = fido_uaf_is_supported(json_reg, &is_supported);

	if (ret != FIDO_ERROR_NONE) {
		char *error_string = __get_error_code(ret);

		printf("Check policy resonse: %s\n", error_string);
		fflush(stdout);
		free(error_string);
	} else {
		if (is_supported == true) {
			printf("Check policy resonse: TRUE\n");
			fflush(stdout);
		} else {
			printf("Check policy resonse: FALSE\n");
			fflush(stdout);
		}
	}
	get_user_choice();
}

void
registration(void)
{
	int ret = fido_uaf_get_response_message(json_reg, NULL, __process_cb, NULL);
	if (ret != FIDO_ERROR_NONE) {
		__show_error(ret);
		get_user_choice();
	}
}

static void
_process_cb(fido_error_e tizen_error_code, const char *uaf_response, void *user_data)
{
	if (tizen_error_code == 0 && uaf_response != NULL) {
		fflush(stdout);
		printf("UAF Response =%s\n", uaf_response);
		fflush(stdout);
	} else {
		__show_error(tizen_error_code);
	}
	get_user_choice();
}

void
authentication(void)
{
	if (json_auth != NULL) {
		int ret = fido_uaf_get_response_message(json_auth, NULL, _process_cb, NULL);

		if (ret != FIDO_ERROR_NONE) {
			__show_error(ret);
			get_user_choice();
		}
	}
}

static void
_process_dereg_cb(fido_error_e tizen_error_code, const char *uaf_response, void *user_data)
{
	char *str = __get_error_code(tizen_error_code);
	printf("%s\n", str);
	fflush(stdout);
	free(str);
	get_user_choice();
}

void
dereg(void)
{
	if (json_reg != NULL) {
		int ret = fido_uaf_get_response_message(json_dereg, NULL, _process_dereg_cb, NULL);

		if (ret != FIDO_ERROR_NONE) {
			__show_error(ret);
			get_user_choice();
		}
	}
}

static void
_process_cb_for_notify_pos(fido_error_e tizen_error_code, const char *uaf_response, void *user_data)
{
	if (tizen_error_code == 0) {

		int ret = fido_uaf_set_server_result(FIDO_SERVER_STATUS_CODE_OK, uaf_response);

		char *str = __get_error_code(ret);
		printf("%s\n", str);
		fflush(stdout);
		free(str);
	} else {
		__show_error(tizen_error_code);
	}
	get_user_choice();
}

void
set_result_success(void)
{
	if (json_reg != NULL) {
		int ret = fido_uaf_get_response_message(json_reg, NULL, _process_cb_for_notify_pos, NULL);

		if (ret != FIDO_ERROR_NONE) {
			__show_error(ret);
			get_user_choice();
		}
	}
}

static void
_process_cb_for_notify_neg(fido_error_e tizen_error_code, const char *uaf_response, void *user_data)
{
	if (tizen_error_code == 0) {

		int ret = fido_uaf_set_server_result(0, uaf_response);
		if (ret == FIDO_ERROR_NONE) {
			printf("SUCCESS\n");
		} else {
			char *str = __get_error_code(ret);
			printf("Error Code = %s\n", str);
			free(str);
		}
		fflush(stdout);		
	} else {
		__show_error(tizen_error_code);
	}
	get_user_choice();
}

void
set_result_failure(void)
{
	if (json_reg != NULL) {
		int ret = fido_uaf_get_response_message(json_reg, NULL, _process_cb_for_notify_neg, NULL);

		if (ret != FIDO_ERROR_NONE) {
			__show_error(ret);
			get_user_choice();
		}
	}
}

void
get_user_choice(void)
{
	int sel_opt = 0;
	const int options[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	const char *names[8] = { 	"Find Authenticator",
								"Check UAF Message Supported",
								"Registration",
								"Authentication",
								"De-Registration",
								"Set Server Result with Success",
								"Set Server Result with Failure",
								"Exit"};

	sel_opt = show_menu("Select action:", options, names, 8);
	switch (sel_opt) {
	case 1:
		find_auth();
		break;

	case 2:
		check_supported();
		break;

	case 3:
		registration();
		break;

	case 4:
		authentication();
		break;

	case 5:
		dereg();
		break;

	case 6:
		set_result_success();
		break;

	case 7:
		set_result_failure();
		break;

	default:
		exit(1);
	}
}

int
main(void)
{
	GMainLoop *mainloop = NULL;

	mainloop = g_main_loop_new(NULL, FALSE);

	get_user_choice();

	g_main_loop_run(mainloop);
 
	return 0;
}
