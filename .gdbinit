set confirm off
#target remote 127.0.0.1:25000
symbol-file ctn-d
file ctn-d
set disassemble-next-line auto
set args -u 0 -m ./busybox-rootfs/ -c /bin/sh
layout split
run
