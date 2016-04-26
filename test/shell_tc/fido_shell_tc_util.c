/**
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 */

#include "fido_shell_tc_util.h"
#include "fido.h"

#include <string.h>
#include <stdio.h>
#include <dlog.h>

void
print_fail_result(
		const char *action_name,
		int action_return_value)
{
	printf(TEXT_RED
			"Error with code %i was occurred during action '%s'"
			TEXT_RESET "\n",
			action_return_value,
			action_name);
}

void 
print_done_result(const char *action_name)
{
	printf(TEXT_YELLOW
			"Action '%s' was finished"
			TEXT_RESET "\n",
			action_name);
}

void 
print_success_result(const char *action_name)
{
	printf(TEXT_GREEN
			"Action '%s' was finished successfully"
			TEXT_RESET
			"\n", action_name);
}

void 
print_action_result(
		const char *action_name,
		int action_return_value,
		notification_type_e notification_type_e)
{
	switch (notification_type_e) {
	case FAIL_OR_SUCCESSS:
		if (FIDO_ERROR_NONE != action_return_value)
			print_fail_result(action_name, action_return_value);
		else
			print_success_result(action_name);

		break;
	case FAIL_OR_DONE:
		if (FIDO_ERROR_NONE != action_return_value)
			print_fail_result(action_name, action_return_value);
		else
			print_done_result(action_name);

		break;
	default:
		print_done_result(action_name);
	}
}

int 
input_string(const char *prompt, size_t max_len, char **string)
{
	printf("\n");
	printf("%s ", prompt);

	if (scanf("\n") != 0)
		return -1;

	char buffer[max_len];
	int last_char = 0;
	buffer[last_char] = '\0';
	buffer[sizeof(buffer) - 1] = ~'\0';
	if (NULL == fgets(buffer, sizeof(buffer), stdin))
		return -1;

	size_t real_string_len = strlen(buffer);
	buffer[real_string_len - 1] = '\0';
	*string = (char*)malloc(real_string_len * sizeof(char));
	if (*string == NULL)
		return -1;

	strncpy(*string, buffer, real_string_len);

	return strlen(*string);
}

int 
input_size(const char *prompt, size_t max_size, size_t *size)
{
	printf("\n");
	printf("%s ", prompt);

	if (scanf("%20zu", size) == 0) {
		if (scanf("%*[^\n]%*c") != 0) {
			printf("ERROR: Reading the input line error.\n");
			return -1;
		}
		printf("ERROR: Incorrect input.\n");
		return -1;
	}
	scanf("%*[^\n]%*c");

	return (*size > max_size ? -1 : 0);
}

int
input_int(const char *prompt, int min_value, int max_value, int *value)
{
	printf("\n");
	printf("%s ", prompt);

	if (scanf("%20i", value) == 0) {
		if (scanf("%*[^\n]%*c") != 0) {
			printf("ERROR: Reading the input line error.\n");
			return -1;
		}
		printf("ERROR: Incorrect input.\n");
		return -1;
	}
	scanf("%*[^\n]%*c");

	return (*value < min_value || *value > max_value ? -1 : 0);
}

int 
input_double(
		const char *prompt,
		double min_value,
		double max_value,
		double *value)
{
	printf("\n");
	printf("%s ", prompt);

	if (scanf("%20lf", value) == 0) {
		if (scanf("%*[^\n]%*c") != 0) {
			printf("ERROR: Reading the input line error.\n");
			return -1;
		}
		printf("ERROR: Incorrect input.\n");
		return -1;
	}
	scanf("%*[^\n]%*c");

	return (*value < min_value || *value > max_value ? -1 : 0);
}

bool 
show_confirm_dialog(const char *title)
{
	const int options[2] = {1, 2};
	const char *names[2] = { "No", "Yes" };

	bool answer = false;

	int sel = -1;
	while (sel == -1) {
		sel = show_menu(title, options, names, 2);
		switch (sel) {
		case 1:
			answer = false;
			break;
		case 2:
			answer = true;
			break;
		default:
			sel = -1;
			printf("ERROR: Incorrect input.\n");
			continue;
		}
	}

	return answer;
}

int 
show_menu(
		const char *title,
		const int *options,
		const char **names,
		int number_of_option)
{
	if (NULL == title || NULL == options || NULL == names || 0 >= number_of_option)
		return -1;

	int number_size = 1;

	int tn_counter = number_of_option;
	while (tn_counter /= 10)
		++number_size;

	int max_len = strlen(title) - number_size - 2;

	int i = 0;
	for (i = 0; i < number_of_option; ++i) {
		const int temp_len = strlen(names[i]);
		if (max_len < temp_len)
			max_len = temp_len;
	}

	const int full_size = number_size + 2 + max_len;

	printf("\n**");
	for (i = 0; i < full_size; ++i)
		printf("*");
	printf("**\n");

	printf("* %-*s *\n", full_size, title);

	printf("*-");
	for (i = 0; i < full_size; ++i)
		printf("-");
	printf("-*\n");

	for (i = 0; i < number_of_option; ++i)
		printf("* %0*i. %-*s *\n", number_size, options[i], max_len, names[i]);

	printf("**");
	for (i = 0; i < full_size; ++i)
		printf("*");
	printf("**\n\n");

	int selection = 0;
	printf("Your choice: ");
	if (scanf("%25i", &selection) == 0) {
		if (scanf("%*[^\n]%*c") != 0)
			printf("ERROR: Reading the input line error.\n");

		printf("ERROR: Incorrect input.\n");
		return -1;
	}
	scanf("%*[^\n]%*c");

	return selection;
}

