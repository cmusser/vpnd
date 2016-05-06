#!/bin/sh

help() {
    echo 'test.sh [-i interface] [-m client|server] [-n remote_net] [-s remote_server] [-d]'
    echo
    echo '  -i is optional (use it the first time after boot)'
    echo '  if -m is unspecified, -n and -s must be, and -d is implied'
    echo '  -d means do not start the nc(1) program to test'
}

while getopts ":i:m:a:n:s:dh" opt ; do

    case $opt in
	i)
	    LOCAL_INTF=$OPTARG
	    ;;
	
	m)
	    if [ $OPTARG = "client" ] ; then
		MODE=$OPTARG
		DEFAULT_LOCAL_ADDR="192.168.2.1/24"
		DEFAULT_REMOTE_SERVER="192.168.3.1"
		DEFAULT_REMOTE_NETWORK="192.168.3.0/24"
	    elif [ $OPTARG = "server" ] ; then
		MODE=$OPTARG
		DEFAULT_LOCAL_ADDR="192.168.3.1/24"
		DEFAULT_REMOTE_SERVER="0.0.0.0"
		DEFAULT_REMOTE_NETWORK="192.168.2.0/24"
	    fi
	    ;;
	
	a)
	    CUSTOM_LOCAL_ADDR=$OPTARG
	    ;;

	n)
	    CUSTOM_REMOTE_NETWORK=$OPTARG
	    ;;

	s)
	    CUSTOM_REMOTE_SERVER=$OPTARG
	    ;;

	d)
	    DONT_START_TEST=true
	    ;;

	h)
	    help
	    exit 0
	    ;;

	\?)
	    echo "Invalid option: -$OPTARG" >&2
	    help
	    exit 1
	    ;;
    esac
    shift
done

LOCAL_ADDR=${CUSTOM_LOCAL_ADDR:-${DEFAULT_LOCAL_ADDR}}
REMOTE_NETWORK=${CUSTOM_REMOTE_NETWORK:-${DEFAULT_REMOTE_NETWORK}}
REMOTE_SERVER=${CUSTOM_REMOTE_SERVER:-${DEFAULT_REMOTE_SERVER}}
echo local address: ${LOCAL_ADDR:?'specify -a (local address) or use -r with "client" or "server"'}
echo remote network: ${REMOTE_NETWORK:?'specify -n (remote network) or use -r with "client" or "server"'}
echo mode: ${MODE:-"no mode set, (test disabled)"}

if [ ! -z ${LOCAL_INTF+x} ] ; then
    echo adding ${LOCAL_ADDR} to ${LOCAL_INTF}
    sudo ifconfig ${LOCAL_INTF} alias ${LOCAL_ADDR}
fi

if [ `uname` = 'DragonFly' ] ; then
    TUN_ADDRS=" inet 10.0.0.1 10.0.0.2"
else
    TUN_ADDRS=""
fi
sudo ifconfig tun0 ${TUN_ADDRS} up
sudo route add ${REMOTE_NETWORK} -interface tun0

if [ -z ${DONT_START_TEST+x} ] && [ ! -z "${MODE+x}" ]; then
    if [ ${MODE} = "client" ] ; then
	TEST_CMD="netcat -s `echo ${LOCAL_ADDR} | cut -f1 -d/` ${REMOTE_SERVER} 2323"
    elif  [ ${MODE} = "server" ] ; then
	TEST_CMD="netcat -l -s `echo ${LOCAL_ADDR} | cut -f1 -d/` -p 2323"
    else
	echo "unknown test mode ${MODE}"
	exit 1
    fi

    echo $MODE mode
    echo ${TEST_CMD}
    ${TEST_CMD}
fi
