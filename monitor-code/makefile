# Project: MemMonitor
# Makefile created by ryan

CPP      = g++
CC       = gcc
CSRC     = monitor.c
OBJ      = $(CSRC:.c=.o)
LINKOBJ  = $(CSRC:.c=.o)
LIBS     = -I/usr/include/mysql -lvmi -lmysqlclient -L/usr/lib/ 
INCS     = 
CXXINCS  = 
BIN      = MemMonitor
CXXFLAGS = $(CXXINCS) 
CFLAGS   = $(INCS) 
RM       = rm -f
.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LINKOBJ) -o $(BIN) $(LIBS)
# ---------------------------------------------------------------------------
# rules for code generation
# ---------------------------------------------------------------------------
%.o:    %.c
	$(CC) $(CFLAGS) -o $@ $(LIBS) -c $<

%.o:    %.S
	$(CC) $(ASFLAGS) -o $@ -c $<
