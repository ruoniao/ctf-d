if=/dev/zero of=/tmp/memoryhog bs=1M count=1024

# 将文件加载到内存中
cat /tmp/memoryhog > /root/1 &

# 循环等待，确保脚本一直在运行
while true; do
	    sleep 1
    done

