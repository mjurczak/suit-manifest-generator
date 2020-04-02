CC = gcc
CFLAGS = -g -ggdb -I../source -I.
CFLAGS += -I../source/uecc
CFLAGS += -DuECC_WORD_SIZE=1

ODIR=build/objs

CFILES = ../source/suit_parser.c ../source/suit_bootloader.c stubs.c
CFILES += ../source/uecc/uECC.c 

CFILES_TEST1 = $(CFILES) main1.c
OBJS_TEST1 = $(patsubst %.c,$(ODIR)/%.o,$(CFILES_TEST1))

CFILES_TEST2 = $(CFILES) main2.c
OBJS_TEST2 = $(patsubst %.c,$(ODIR)/%.o,$(CFILES_TEST2))

CFILES_TEST3 = $(CFILES) main3.c
OBJS_TEST3 = $(patsubst %.c,$(ODIR)/%.o,$(CFILES_TEST3))

.PHONY: test_1
test_1: $(OBJS_TEST1)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: test_2
test_2: $(OBJS_TEST2)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: test_3
test_3: $(OBJS_TEST3)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -rf build

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS)