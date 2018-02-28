#include <dbus/dbus.h>
struct dbus_sig_t {
    char *dbus_name;
    char *iter_name;
    char *obj_name;
    char *name;
    void **argv;
    int argc;
    int *dbus_types;
    void (*callback)(struct dbus_sig_t *sig, DBusMessageIter args);
    DBusBusType type;
};

typedef struct dbus_sig_t dbus_sig;

void send_sig(dbus_sig *sig);
void recv_sig(dbus_sig **sig);
