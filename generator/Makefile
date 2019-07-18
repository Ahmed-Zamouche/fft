#
# 'make depend' uses makedepend to automatically generate dependencies
#               (dependencies are added to end of Makefile)
# 'make'        build executable file 'mycc'
# 'make clean'  removes all .o and executable files
#

# define the C compiler to use
CC = gcc

CDEFS:= -D__USE_MINGW_ANSI_STDIO

# define any compile-time flags
CFLAGS = -Wall -g $(CDEFS)


# define any directories containing header files other than /usr/include
#
INCLUDES = -I./inc -I../inc

SRCSDIR= .
OBJSDIR= ./obj
BINDIR = ./bin

# define library paths in addition to /usr/lib
#   if I wanted to include libraries not in /usr/lib I'd specify
#   their path using -Lpath, something like:
#LFLAGS = -L/home/newhall/lib  -L../lib
LFLAGS = -L./lib

# define any libraries to link into executable:
#   if I want to link in libraries (libx.so or libx.a) I use the -llibname
#   option, something like (this will link in libmylib.so and libm.so:
#LIBS = -lmylib -lm
LIBS = -lm

# define the C source files
SRCS = src/fft_gen.c src/fft_f32_gen.c src/fft_q8_7_gen.c

# define the C object files
#
# This uses Suffix Replacement within a macro:
#   $(name:string1=string2)
#         For each word in 'name' replace 'string1' with 'string2'
# Below we are replacing the suffix .c of all words in the macro SRCS
# with the .o suffix
#
OBJS = $(SRCS:$(SRCSDIR)/%.c=$(OBJDIR)/%.o)
#OBJS = $(addprefix $(OBJSDIR)/, $(_OBJS))

# define the executable file
MAIN = fft_gen

#
# The following part of the makefile is generic; it can be used to
# build any executable just by changing the definitions above and by
# deleting dependencies appended to the file from 'make depend'
#

.PHONY: depend clean

all:    $(MAIN)
	@echo  $(BINDIR)/$(MAIN) has been compiled

$(MAIN): $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(BINDIR)/$(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

# this is a suffix replacement rule for building .o's from .c's
# it uses automatic variables $<: the name of the prerequisite of
# the rule(a .c file) and $@: the name of the target of the rule (a .o file)
# (see the gnu make manual section about automatic variables)
.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $(OBJSDIR)/$@

clean:
	$(RM) -r $(OBJSDIR) $(BINDIR)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

# DO NOT DELETE THIS LINE -- make depend needs it