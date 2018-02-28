
CC=gcc
CCFLAGS=-Wall
INC=`pkg-config --cflags --libs glib-2.0 gio-unix-2.0 gio-2.0`

SERVER=gdbus-example-server
CLIENT=gdbus-example-unix-fd-client

all: $(SERVER) $(CLIENT)

$(SERVER): $(SERVER).o
	$(CC) -o $@ $^ $(INC)

$(CLIENT): $(CLIENT).o
	$(CC) -o $@ $^ $(INC)

%.o: %.c %.h
	$(CC) $(INC) $(CCFLAGS) -c $<

%.o: %.c
	$(CC) $(INC) $(CCFLAGS) -c $<

clean:
	rm -f *.o $(TARGET) $(SERVER) $(CLIENT)
