MAKEFLAGS += -s

NAME = cloak

NASM 	= /usr/bin/nasm
CCx64 	= /usr/local/bin/zig c++

ZFLAGS	  = -target x86_64-windows
ZFLAGS	  +=  -Os -fno-asynchronous-unwind-tables -masm=intel
ZFLAGS	  += -fno-ident -fpack-struct=8 -falign-functions=1
ZFLAGS    += -s -ffunction-sections -falign-jumps=1 -w
ZFLAGS	  += -falign-labels=1 -fPIC -fpermissive
ZFLAGS	  += -Wl,-s

SOURCE = $(wildcard src/*)
INCLUDE = -I include

PAYLOAD_PATH = ./demon.bin

TIMESTAMP = 201512181932.24

exe: clean metadata x64-exe

dll: clean x64-dll

metadata:
	/usr/bin/x86_64-w64-mingw32-windres -i ./cloak.rc -o src/cloak.o

x64-exe:
	printf "\033[0;36m[*]\033[0m Starting EXE Build\n"

	$(CCx64) $(SOURCE) $(INCLUDE) $(ZFLAGS) -lcrypt32 -m64 -o bin/$(NAME).exe

	printf "\033[0;32m[+]\033[0m Finished EXE Build\n"

x64-dll:
	printf "\033[0;36m[*]\033[0m Starting DLL Build\n"

	$(CCx64) $(SOURCE) $(INCLUDE) $(CFLAGS) -m64 -shared -o bin/$(NAME).dll

	printf "\033[0;32m[+]\033[0m Finished DLL Build\n"

clean:
	rm -rf bin/*.exe
	rm -rf src/*.o
	rm -rf bin/*.dll
