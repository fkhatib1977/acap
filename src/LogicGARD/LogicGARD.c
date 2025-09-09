#include <microhttpd.h>
#include <axsdk/axevent.h>
#include <axsdk/axevent/ax_event.h>
#include <glib-object.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include "cJSON.h"

#define PORT 5001
#define BUFFER_SIZE 1024
#define TEMP_THRESHOLD 30.0

static char latest_temp[BUFFER_SIZE] = "N/A";
static struct MHD_Daemon *http_daemon = NULL;
static AXEventHandler *event_handler = NULL;
static guint event_declaration_id = 0;

struct ConnectionInfo {
    char buffer[BUFFER_SIZE];
    size_t offset;
};

static void declare_event() {
    AXEventKeyValueSet *key_value_set = ax_event_key_value_set_new();
    guint token = 0;
    gdouble dummy_value = 0.0;
    GError *error = NULL;

	ax_event_key_value_set_add_key_value(key_value_set, "topic0", "tns1", "LogicGARD2", AX_VALUE_TYPE_STRING, NULL);
	ax_event_key_value_set_add_key_value(key_value_set, "topic1", "tns1", "Temperature", AX_VALUE_TYPE_STRING, NULL);
    ax_event_key_value_set_add_key_value(key_value_set, "Token", NULL, &token, AX_VALUE_TYPE_INT, NULL);
    ax_event_key_value_set_add_key_value(key_value_set, "Value", NULL, &dummy_value, AX_VALUE_TYPE_DOUBLE, NULL);

    ax_event_key_value_set_mark_as_source(key_value_set, "Token", NULL, NULL);
    ax_event_key_value_set_mark_as_user_defined(key_value_set, "Token", NULL, "wstype:tt:ReferenceToken", NULL);
    ax_event_key_value_set_mark_as_data(key_value_set, "Value", NULL, NULL);
    ax_event_key_value_set_mark_as_user_defined(key_value_set, "Value", NULL, "wstype:xs:float", NULL);

	if (!ax_event_handler_declare(event_handler,
							  key_value_set,
							  FALSE,  // Indicate a property state event
							  &event_declaration_id,
							  NULL,
							  dummy_value,
							  &error)) {
        syslog(LOG_WARNING, "Could not declare: %s", error->message);
        g_error_free(error);
    }

    ax_event_key_value_set_free(key_value_set);

    if (error) {
        syslog(LOG_ERR, "❌ Event declaration failed: %s", error->message);
        g_error_free(error);
    } else {
        syslog(LOG_INFO, "📣 Event declared successfully");
    }
}

static void raise_event(float temp) {
    AXEventKeyValueSet *key_value_set = ax_event_key_value_set_new();
    AXEvent *event = NULL;

    ax_event_key_value_set_add_key_value(key_value_set, "Value", NULL, &temp, AX_VALUE_TYPE_DOUBLE, NULL);
    event = ax_event_new2(key_value_set, NULL);
    ax_event_key_value_set_free(key_value_set);

    ax_event_handler_send_event(event_handler, event_declaration_id, event, NULL);
    ax_event_free(event);

    syslog(LOG_INFO, "📡 Raised temperature event: %.2f°C", temp);
}

enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection,
                               const char *url, const char *method,
                               const char *version, const char *upload_data,
                               size_t *upload_data_size, void **con_cls) {
    static const char *response_str;
    struct ConnectionInfo *con_info;

    if (*con_cls == NULL) {
        con_info = calloc(1, sizeof(struct ConnectionInfo));
        *con_cls = con_info;
        return MHD_YES;
    }

    con_info = *con_cls;

    if (strcasecmp(url, "/LogicGARD/Temperature") == 0) {
        if (strcmp(method, "POST") == 0) {
            if (*upload_data_size > 0) {
                size_t len = (*upload_data_size < BUFFER_SIZE - con_info->offset - 1)
                             ? *upload_data_size : BUFFER_SIZE - con_info->offset - 1;
                memcpy(con_info->buffer + con_info->offset, upload_data, len);
                con_info->offset += len;
                con_info->buffer[con_info->offset] = '\0';
                *upload_data_size = 0;
                return MHD_YES;
            }

            // Full body received, now parse JSON
            cJSON *json = cJSON_Parse(con_info->buffer);
            if (!json) {
                syslog(LOG_ERR, "❌ Failed to parse JSON");
                response_str = "Invalid JSON\n";
            } else {
                cJSON *temp_item = cJSON_GetObjectItem(json, "temperature");
                if (cJSON_IsNumber(temp_item)) {
                    float temp = (float)temp_item->valuedouble;
                    snprintf(latest_temp, BUFFER_SIZE, "%.2f", temp);
                    syslog(LOG_INFO, "📥 Received temperature (JSON): %.2f°C", temp);

                    raise_event(temp);
					syslog(LOG_INFO, "event raised");

                    response_str = "Temperature updated\n";
                } else {
                    syslog(LOG_WARNING, "⚠️ 'temperature' field missing or not a number");
                    response_str = "Missing or invalid 'temperature' field\n";
                }
                cJSON_Delete(json);
            }
        } else if (strcmp(method, "GET") == 0) {
            response_str = latest_temp;
        } else {
            syslog(LOG_WARNING, "⚠️ Unsupported method: %s", method);
            response_str = "Unsupported method\n";
        }
    } else {
        response_str = "Not found\n";
    }

    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_str),
                                                                    (void *)response_str,
                                                                    MHD_RESPMEM_PERSISTENT);
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

void stop_server(int signum) {
    syslog(LOG_INFO, "🛑 Server stopping...");

    if (http_daemon) {
        MHD_stop_daemon(http_daemon);
        syslog(LOG_INFO, "🛑 HTTP server stopped");
    }
    if (event_handler) {
        ax_event_handler_undeclare(event_handler, event_declaration_id, NULL);
        ax_event_handler_free(event_handler);
        syslog(LOG_INFO, "🛑 Event handler cleaned up");
    }

    closelog();
    exit(0);
}

int main() {
    signal(SIGINT, stop_server);

    openlog("LogicGARD", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "🚀 LogicGARD starting up...");

    event_handler = ax_event_handler_new();
    if (!event_handler) {
        syslog(LOG_ERR, "❌ Failed to initialize AXEventHandler");
        return 1;
    }
    syslog(LOG_INFO, "✅ AXEventHandler initialized");

    declare_event();

    http_daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
                                   &handle_request, NULL, MHD_OPTION_END);
    if (http_daemon == NULL) {
        syslog(LOG_ERR, "❌ Failed to start HTTP server on port %d", PORT);
        return 1;
    }

    syslog(LOG_INFO, "🌐 HTTP API running on port %d", PORT);
    while (1) pause();

    closelog();
    return 0;
}
