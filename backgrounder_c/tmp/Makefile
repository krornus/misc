CC=gcc
DEPS=dbus.c
FLAGS=-Wall -g

INC=-I/usr/include/dbus-1.0
INC+=-I/usr/include/glib-2.0 
INC+=-I/usr/lib/dbus-1.0/include
INC+=-ldbus-1
INC+=-ldbus-glib-1

CFLAGS=-I. $(INC) $(FLAGS) 

ODIR=obj
_OBJ=backgrounder.o dbus.o
OBJ=$(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

backgrounder: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean: 
	rm -f $(ODIR)/*.o backgrounder 
