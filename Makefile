#KDIR=/lib/modules/$(shell uname -r)/build
KDIR=/home/tapan/digichip/tapan/digichip/linux/linux-4.0
obj-m += bclient.o
obj-m += bserver.o
bclient-objs := bio_client.o tcpio_client.o tcpio_common.o bio_cfio.o bio_cctl.o
bserver-objs := bio_server.o tcpio_server.o tcpio_common.o bio_sfio.o bio_sctl.o
all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
