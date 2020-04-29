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

CLANG_OPTIONS = -enable-checker alpha.core.BoolAssignment \
    -enable-checker alpha.core.Conversion \
    -enable-checker alpha.core.CastSize \
    -enable-checker alpha.core.CastToStruct \
    -enable-checker alpha.core.DynamicTypeChecker \
    -enable-checker alpha.core.FixedAddr \
    -enable-checker alpha.core.IdenticalExpr \
    -enable-checker alpha.core.PointerArithm \
    -enable-checker alpha.core.PointerSub \
    -enable-checker alpha.core.SizeofPtr \
    -enable-checker alpha.core.TestAfterDivZero \
    -enable-checker alpha.deadcode.UnreachableCode \
    -enable-checker alpha.security.ArrayBound \
    -enable-checker alpha.security.ArrayBoundV2 \
    -enable-checker alpha.security.MallocOverflow \
    -enable-checker alpha.security.ReturnPtrRange \
    -enable-checker alpha.security.taint.TaintPropagation \
    -enable-checker alpha.unix.cstring.BufferOverlap \
    -enable-checker alpha.unix.cstring.NotNullTerminated \
    -enable-checker alpha.unix.cstring.OutOfBounds \
    -enable-checker nullability.NullableDereferenced \
    -enable-checker nullability.NullablePassedToNonnull \
    -enable-checker security.FloatLoopCounter \
    -enable-checker security.insecureAPI.strcpy

.PHONY: test_1
test_1: $(OBJS_TEST1)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: test_2
test_2: $(OBJS_TEST2)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: test_3
test_3: $(OBJS_TEST3)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: static_clang
static_clang:
	scan-build -v $(CLANG_OPTIONS) -maxloop 512 -o scan_report gcc -I../source/uecc -I. -c ../source/suit_parser.c ../source/suit_bootloader.c

.PHONY: static_cppcheck
static_cppcheck:
	cppcheck -v --enable=warning --enable=style --enable=portability --enable=information ../source/suit_parser.c ../source/suit_bootloader.c

.PHONY: clean
clean:
	rm -rf build

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS)