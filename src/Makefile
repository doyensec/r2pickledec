CC = gcc
INSTAL_LOC=~/.local/share/radare2/plugins
TARGET = pickle_dec.so
CFLAGS = -g -shared -fPIC -Wall $(shell pkg-config --libs --cflags r_core r_util)
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

ALL = $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

asan: CFLAGS+=-fsanitize=address
asan: $(TARGET)

.PHONY: clean install uninstall
install: $(TARGET)
	install $(TARGET) $(INSTAL_LOC)/$(TARGET)
uninstall:
	rm /opt/$(TARGET)
clean:
	rm -f $(OBJ) $(TARGET)
