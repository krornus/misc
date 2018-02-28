#include <unistd.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dbus.h"

#define BG_SCALE "--bg-scale"
#define BG_MAX "--bg-max"
#define BG_FILL "--bg-fill"
#define BG_CENTER "--bg-center"
#define BG_TILE "--bg-tile"
#define BG_SEAMLESS "--bg-seamless"
#define ARG_NAME_LEN 128

int set_background(char *file, char *mode);
void sig_callback(dbus_sig *sig, DBusMessageIter args);
dbus_sig *init_str_sig(char *name, int argc, char **args);
void destroy_sig(dbus_sig *sig);

int main(int argc, char **argv)
{
    dbus_sig *sig;
    dbus_sig *sig2;

    char *args[] = { "skippit", "arg2" };
    char *args2[] = { "next" };

    sig = init_str_sig("settings", 2, args);
    sig2 = init_str_sig("action", 1, args2);
    dbus_sig *signals[] = { sig, sig2, NULL };

    if(argc != 2) {
        fprintf(stderr, "usage: ./backgrounder <arg>\n");
        exit(-1);
    }

    if(strcmp(argv[1], "send") == 0) {
        send_sig(sig);
        send_sig(sig2);
    }
    else if(strcmp(argv[1], "recv") == 0) {
        recv_sig(signals);
    }
    else {
        fprintf(stderr, "unrecognized argument '%s'\n\texpecting 'send|recv'\n", argv[1]);
        exit(-1);
    }

    destroy_sig(sig);
    destroy_sig(sig2);
}

void sig_callback(dbus_sig *sig, DBusMessageIter args)
{
    printf("signal received from %s\n", sig->name);
    if(!dbus_message_iter_has_next(&args))
        return;
    do {
        char *val;
        dbus_message_iter_get_basic(&args, &val);
        printf("\targ: '%s'\n", val);
    } while(dbus_message_iter_next(&args));
}

int set_background(char *file, char *mode)
{
    /* TODO: actually do this instead of the hot garbage before you     */
    /* feh handles more, and this shouldn't be getting called too often */
    int child;

    child = fork();

    if(child == 0)
        execl("./tool/feh", "feh", mode, file, (char *)NULL);
    return child;
}

dbus_sig *init_str_sig(char *name, int argc, char **args)
{
    dbus_sig *sig;
    int *types;

    sig = malloc(sizeof(dbus_sig));
    types = malloc(sizeof(int)*argc);

    for(int i = 0; i < argc; i++)
    {
        types[i] = DBUS_TYPE_STRING;
    }

    sig->dbus_name = "backgrounder.signal.source";
    sig->iter_name = "backgrounder.signal.args";
    sig->obj_name = "/backgrounder/signal/Object";
    sig->name = name;
    sig->argv = (void **)args;
    sig->argc = argc;
    sig->dbus_types = types;
    sig->callback = sig_callback;
    sig->type = DBUS_BUS_SESSION;

    return sig;
}

void destroy_sig(dbus_sig *sig)
{
    free(sig->dbus_types);
    free(sig);
}
