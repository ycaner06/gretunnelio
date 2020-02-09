TARGET= gretunelkur
CFLAGS=		-g -Wall -Wstrict-prototypes -fno-strict-aliasing -std=c99
SRCS= main.c
all: 
	gcc $(CFLAGS) $(SRCS) -o $(TARGET)
clean: 
	rm -rf *.so
