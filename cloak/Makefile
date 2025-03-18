MAKEFLAGS += -s

NAME = cloak

NASM = /usr/bin/nasm
CCx64 = /usr/bin/x86_64-w64-mingw32-g++


CFLAGS	  =  -Os -fno-asynchronous-unwind-tables -masm=intel
CFLAGS	  += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS    += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	  += -falign-labels=1 -fPIC
CFLAGS	  += -Wl,-s,--no-seh,--enable-stdcall-fixup

SOURCE = $(wildcard src/*)
INCLUDE = -I include

PAYLOAD_PATH = ./demon.bin

all: clean x64

x64:
	printf "\033[0;36m[*]\033[0m Starting Build\n"

	$(CCx64) $(SOURCE) $(INCLUDE) $(CFLAGS) -m64 -o bin/$(NAME).exe

	printf "\033[0;36m[+]\033[0m Finished Build\n"

add-payload:
	

clean:
	rm -rf bin/*.exe
