ip link set wlxe84e066ce852 down
ip link set wlxe84e066ce852 name wlan0
iw wlan0 set type monitor
ip link set wlan0 up

ip link set enp0s3 down
ip link set enp0s3 promisc on
ip link set enp0s3 up