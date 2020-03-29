CC = gcc
CFLAGS = -g -ggdb -I../source -I.
CFLAGS += -I../source/uecc

ODIR=build/objs

CFILES = ../source/suit_parser.c ../source/suit_bootloader.c stubs.c main.c
CFILES += ../source/uecc/uECC.c ../source/uecc/uECC_ll.c
OBJS = $(patsubst %.c,$(ODIR)/%.o,$(CFILES))

.PHONY: test_app
test_app: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -rf $(ODIR) 

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS)