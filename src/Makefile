CC = gcc
INSTAL_LOC=~/.local/share/radare2/plugins
NAME = pickle_dec
TARGET = $(NAME).so
CFLAGS = -g -shared -fPIC -Wall $(shell pkg-config --libs --cflags r_core r_util)
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
