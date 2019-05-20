#!/bin/bash

SWID=$1
# might be pf0vf1 so only get vf number
PORT=${2##*f}
PORT_NAME=$2

is_bf=`lspci -s 00:00.0 2> /dev/null | grep -wq "PCI bridge: Mellanox Technologies" && echo 1 || echo 0`
if [ $is_bf -eq 1 ]; then
	case "$2" in
		pf[0-1])
			echo NAME=${2}hpf
		;;
		*)
			echo NAME=${2}
		;;
	esac
	exit 0
fi

# for pf and uplink rep fall to slot or path.
if [ -n "$ID_NET_NAME_SLOT" ]; then
    echo "NAME=$ID_NET_NAME_SLOT"
    exit
fi

if [ -n "$ID_NET_NAME_PATH" ]; then
    echo "NAME=$ID_NET_NAME_PATH"
    exit
fi

function get_name() {
    udevadm info -q property -p /sys/bus/pci/devices/$1/net/* | grep $2 | cut -d= -f2
}

# get phys_switch_id by pci
function get_swid() {
    cat /sys/bus/pci/devices/$1/net/*/phys_switch_id 2>/dev/null
}

# get phys_port_name by pci
function get_port_name() {
    cat /sys/bus/pci/devices/$1/net/*/phys_port_name 2>/dev/null
}

# for vf rep get parent slot/path.
parent_phys_port_name=${PORT_NAME%vf*}
parent_phys_port_name=${parent_phys_port_name//f}
# try at most two times
for cnt in {1..2}; do
    for pci in `ls -l /sys/class/net/*/device | cut -d "/" -f9-`; do
        if [ -h /sys/bus/pci/devices/${pci}/physfn ]; then
            continue
        fi
        _swid=`get_swid $pci`
        _portname=`get_port_name $pci`
        if [ -z $_portname ]; then
            # no uplink rep so no phys port name
            _portname=$parent_phys_port_name
        fi
        if [ "$_swid" = "$SWID" ] && [ "$_portname" = "$parent_phys_port_name" ]
        then
            parent_path=`get_name $pci ID_NET_NAME_SLOT`
            if [ -z "$parent_path" ]; then
                parent_path=`get_name $pci ID_NET_NAME_PATH`
            fi
            echo "NAME=${parent_path}_$PORT"
            exit
        fi
    done

    # swid changes when entering lag mode.
    # So if we didn't find current swid, get the updated one.
    SWID=`cat /sys/class/net/$INTERFACE/phys_switch_id`
done
