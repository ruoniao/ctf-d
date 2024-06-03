all:
	gcc -Wl,--no-as-needed -g -lcap -lseccomp ctn-d.c -o ctn-d

run:
	sudo ./ctn-d -u 0 -m ./busybox-rootfs/ -c /bin/echo "hello from inside container"

run-sh:
	sudo ./ctn-d -u 0 -m ./busybox-rootfs/ -c /bin/sh
