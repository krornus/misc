#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dbus.h"

#define DBUS_ERROR(e, msg)\
    fprintf(stderr, "%s:\n\t%s\n", msg, e.message);\
    dbus_error_free(&e);

#define STD_ERROR(msg)\
    fprintf(stderr, msg);\
    exit(-1);

void send_sig(dbus_sig *sig)
{
    DBusConnection *conn;
    DBusMessage *msg;
    DBusMessageIter iter;
    DBusError error;

    dbus_uint32_t serial = 0;

    dbus_error_init(&error);
    conn = dbus_bus_get(sig->type, &error);

    if(dbus_error_is_set(&error)) {
        DBUS_ERROR(error, "dbus_bus_get()");
    }

    if(NULL == conn) {
        STD_ERROR("no connection\n");
        exit(-1);
    }

    dbus_bus_request_name(conn, sig->dbus_name, 
            DBUS_NAME_FLAG_REPLACE_EXISTING, &error);

    if(dbus_error_is_set(&error)){
        DBUS_ERROR(error, "dbus_bus_request_name()\n");
    }

    msg = dbus_message_new_signal(sig->obj_name, sig->iter_name, sig->name);

    if(NULL == msg) {
        STD_ERROR("dbus_message_new_signal()\n\tcannot allocate memory");
    }

    dbus_message_iter_init_append(msg, &iter);

    for(int i = 0; i < sig->argc; i++) {
        if(0 == dbus_message_iter_append_basic(
                    &iter, sig->dbus_types[i], &sig->argv[i])) {
            STD_ERROR("dbus_message_iter_append_basic()\n\
                    \tcannot allocate memory");
        }
    }

    if (!dbus_connection_send(conn, msg, &serial)) {
        STD_ERROR("dbus_connection_send()\n\tcannot allocate memory");
    }

    dbus_connection_flush(conn);
    dbus_message_unref(msg);

    if(sig->type != DBUS_BUS_SESSION) {
        dbus_connection_close(conn);
    }
}


void recv_sig(dbus_sig **signals)
{
    DBusConnection *conn;
    DBusMessage *msg;
    DBusMessageIter iter;
    DBusError error;

    dbus_sig *sig;
    
    int i = 0;
    sig = signals[i];
    while(sig) {
        int rule_length;

        char *rule_base = "type='signal',interface='%s'";
        char *rule;

        dbus_error_init(&error);
        conn = dbus_bus_get(sig->type, &error);

        if(dbus_error_is_set(&error))
            DBUS_ERROR(error, "dbus_bus_get()");

        if(NULL == conn)
            exit(-1);

        dbus_bus_request_name(conn, 
                sig->dbus_name,
                DBUS_NAME_FLAG_REPLACE_EXISTING,
                &error);

        if(dbus_error_is_set(&error))
            DBUS_ERROR(error, "dbus_bus_request_name()");

        rule_length = strlen(rule_base) + strlen(sig->iter_name) + 1;
        rule = (char  *)malloc(rule_length);
        snprintf(rule, rule_length, rule_base, sig->iter_name);

        dbus_bus_add_match(conn, rule, &error);

        free(rule);

        if(dbus_error_is_set(&error)) {
            DBUS_ERROR(error, "dbus_bus_add_match()");
            exit(-1);
        }

        i++;
        sig = signals[i];
    }

    while(1) {
        dbus_connection_read_write(conn, 0);
        msg = dbus_connection_pop_message(conn);

        if (NULL == msg)
            sleep(1);
        else { 
            int i = 0;
            sig = signals[i];
            while(sig){
                if(dbus_message_is_signal(msg, sig->iter_name, sig->name))
                {
                    if(!dbus_message_iter_init(msg, &iter)) {
                        fprintf(stderr, 
                                "dbus_message_iter_init()\n\t\
                                message is parameterless\n");
                    }

                    sig->callback(sig, iter);

                    dbus_message_unref(msg);
                }
                i++;
                sig = signals[i];
            }
        }
    }

}
