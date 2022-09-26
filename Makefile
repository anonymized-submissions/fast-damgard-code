SHELL = /bin/bash
CC = gcc
RM = rm -rf
TAR = tar
MKDIR = mkdir
CHMOD = chmod
CP = cp
MV = mv

PROGNAME = damgard
EXEC = damgard
PACKAGE = $(PROGNAME)
VERSION = 0.3
DISTDIR = $(PACKAGE)-$(VERSION)
HEADERS = decrypt.h encrypt.h hashF.h keyGenerator.h keys.h primitiveRoot.h RandomGenerator.h
SOURCES = decrypt.c encrypt.c hashF.c keyGenerator.c primitiveRoot.c RandomGenerator.c main_damgard.c 

LDFLAGS = -lgmp -L/usr/local/opt/openssl/lib -lm   -lcrypto
CFLAGS = -Wall 

OBJ = $(SOURCES:.c=.o) 
DISTFILES = $(SOURCES) Makefile $(HEADERS) 

all: $(EXEC)  

$(EXEC): $(OBJ)	 
	$(CC) $(OBJ) $(LDFLAGS) -o $(EXEC) 

%.o:%.c $(HEADERS) 
	$(CC) -c $< $(CFLAGS)

dist: distdir
	$(CHMOD) -R a+r $(DISTDIR)
	$(TAR) zcvf $(DISTDIR).tar.gz $(DISTDIR)
	$(RM) $(DISTDIR)

distdir: $(DISTFILES)
	$(RM) $(DISTDIR)
	$(MKDIR) $(DISTDIR)
	$(CHMOD) 777 $(DISTDIR)
	$(CP) -rf $(DISTFILES) $(DISTDIR)
clean:
	$(RM) $(PROGNAME) $(OBJ) *~ $(DISTDIR).tar.gz
