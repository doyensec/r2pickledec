CC = gcc
INSTAL_LOC=~/.local/share/radare2/plugins
NAME = pickle_dec
TARGET = $(NAME).so
CFLAGS := -fPIC -Wall 
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	CCFLAGS += -D LINUX
endif
ifeq ($(UNAME_S),Darwin)
	CCFLAGS += -D OSX
	TARGET = $(NAME).dylib
endif
UNAME_P := $(shell uname -p)
ifeq ($(UNAME_P),x86_64)
	CCFLAGS += -D AMD64
endif
ifneq ($(filter %86,$(UNAME_P)),)
	CCFLAGS += -D IA32
endif
ifneq ($(filter arm%,$(UNAME_P)),)
	CCFLAGS += -D ARM
endif

ALL = $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -shared $(CFLAGS) $(shell pkg-config --libs --cflags r_core r_util) -o $@ $^

pyobjutil.o: pyobjutil.c pyobjutil.h
	$(CC) -shared $(CFLAGS) $(shell pkg-config --libs --cflags r_core r_util) -o $@ pyobjutil.c

dump.o: pyobjutil.o dump.c
	$(CC) -shared $(CFLAGS) $(shell pkg-config --libs --cflags r_util r_config r_cons) -o $@ $^

json_dump.o: pyobjutil.o json_dump.c
	$(CC) -shared $(CFLAGS) $(shell pkg-config --libs --cflags r_core) -o $@ $^

pickle_dec.o: pyobjutil.o dump.o json_dump.o pickle_dec.c
	$(CC) -shared $(CFLAGS) $(shell pkg-config --libs --cflags r_core r_util) -o $@ $^

asan: CFLAGS+=-g -fsanitize=address
asan: $(TARGET)

debug: CFLAGS+=-g
debug: $(TARGET)

.PHONY: clean install uninstall
install: $(TARGET)
	install $(TARGET) $(INSTAL_LOC)/$(TARGET)
uninstall:
	rm /opt/$(TARGET)
clean:
	rm -f $(OBJ) $(TARGET)
