obj-m += tcp_china.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
		install tcp_china.ko /lib/modules/$(shell uname -r)/kernel/net/ipv4
		insmod /lib/modules/$(shell uname -r)/kernel/net/ipv4/tcp_china.ko
		depmod -a
