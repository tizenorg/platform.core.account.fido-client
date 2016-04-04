
#ifndef __FIDO_SHELL_TC_UTIL_H_
#define __FIDO_SHELL_TC_UTIL_H_

#include <stddef.h>
#include <dlog.h>
#include <tizen.h>

#define TEXT_RED     "\x1b[31m"
#define TEXT_GREEN   "\x1b[32m"
#define TEXT_YELLOW  "\x1b[33m"
#define TEXT_BLUE    "\x1b[34m"
#define TEXT_MAGENTA "\x1b[35m"
#define TEXT_CYAN    "\x1b[36m"
#define TEXT_RESET   "\x1b[0m"

#ifdef ROOTSTRAP_OUT

#define LOGD(...)                                 \
do {                                              \
    printf("<%s:%d>", __FUNCTION__, __LINE__);    \
    printf(TEXT_CYAN);                            \
    printf(__VA_ARGS__);                          \
    printf(TEXT_RESET "\n");                      \
} while (0)

#define LOGI(...)                                 \
do {                                              \
    printf("<%s:%d>", __FUNCTION__, __LINE__);    \
    printf(TEXT_GREEN);                           \
    printf(__VA_ARGS__);                          \
    printf(TEXT_RESET "\n");                      \
} while (0)

#define LOGW(...)                                 \
do {                                              \
    printf("<%s:%d>", __FUNCTION__, __LINE__);    \
    printf(TEXT_YELLOW);                          \
    printf(__VA_ARGS__);                          \
    printf(TEXT_RESET "\n");                      \
} while (0)

#define LOGE(...)                                 \
do {                                              \
    printf("<%s:%d>", __FUNCTION__, __LINE__);    \
    printf(TEXT_RED);                             \
    printf(__VA_ARGS__);                          \
    printf(TEXT_RESET "\n");                      \
} while (0)

#endif


typedef enum {
    FAIL_OR_SUCCESSS,
    FAIL_OR_DONE
} notification_type_e;

/**
 * @brief Prints success result of action.
 *
 * @since_tizen 3.0
 * @param [in] action_name           Name of action which result will be printed
 * @param [in] action_return_value   Return value of action
 */
void print_fail_result(
        const char *action_name,
        int action_return_value);

/**
 * @brief Prints success result of action.
 *
 * @since_tizen 3.0
 * @param [in] action_name           Name of action which result will be printed
 */
void print_done_result(const char *action_name);

/**
 * @brief Prints success result of action.
 *
 * @since_tizen 3.0
 * @param [in] action_name           Name of action which result will be printed
 */
void print_success_result(const char *action_name);

/**
 * @brief Prints action result.
 *
 * @since_tizen 3.0
 * @param [in] action_name           Name of action which result will be printed
 * @param [in] action_return_value   Return value of action
 * @param [in] notification_type_e   Type of notification
 */
void print_action_result(
        const char *action_name,
        int action_return_value,
        notification_type_e notification_type_e);

/**
 * @brief Gets srting from console.
 *
 * @since_tizen 3.0
 * @param [in] prompt     The prompt before getting string value
 * @param [in] max_len    Maximum length of the string which will be got
 * @param [out] string    Output string which was got from console
 * @return Length of the output string on success, otherwise a negative error value
 */
int input_string(const char *prompt, size_t max_len, char **string);

/**
 * @brief Gets unsigned integer from console.
 *
 * @since_tizen 3.0
 * @param [in] prompt      The prompt before getting unsigned integer value
 * @param [in] max_size    The thresold for maximum possible value
 * @param [out] size       The output unsigned integer which was got from console
 * @return @c 0 on success, otherwise a negative error value
 */
int input_size(const char *prompt, size_t max_size, size_t *size);

/**
 * @brief Gets integer from console.
 *
 * @since_tizen 3.0
 * @param [in] prompt       The prompt before getting integer value
 * @param [in] min_value    The thresold for minimum possible value
 * @param [in] max_value    The thresold for maximum possible value
 * @param [out] value       The output integer which was got from console
 * @return @c 0 on success, otherwise a negative error value
 */
int input_int(const char *prompt, int min_value, int max_value, int *value);

/**
 * @brief Gets double from console.
 *
 * @since_tizen 3.0
 * @param [in] prompt       The prompt before getting double value
 * @param [in] min_value    The thresold for minimum possible value
 * @param [in] max_value    The thresold for maximum possible value
 * @param [out] value       The output double which was got from console
 * @return @c 0 on success, otherwise a negative error value
 */
int input_double(const char *prompt, double min_value, double max_value, double *value);

/**
 * @brief Shows confirm dialog in console and gets answer (Yes/No).
 *
 * @since_tizen 3.0
 * @param [in] title    The title for confirm dialog which will be printed
 *                      before input of the answer
 * @return false if answer is "No" and true if answer is "Yes"
 */
bool show_confirm_dialog(const char *title);

/**
 * @brief Shows menu in console and allows to get item from the array of options.
 *
 * @since_tizen 3.0
 * @param [in] title               The title for show menu which will be printed
 *                                 before options
 * @param [in] options             The array with integer numbers of options
 *                                 which will be shown
 * @param [in] names               The array with names of options which will
 *                                 be shown
 * @param [in] number_of_option    The number of options which will be shown
 * @return The selected item positive number from options array on success,
 *         otherwise a negative error value
 */
int show_menu(
        const char *title,
        const int *options,
        const char **names,
        int number_of_option);

#endif /* __FIDO_SHELL_TC_UTIL_H_ */
