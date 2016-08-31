#!/usr/bin/env python

import argparse
import daemon
import logging
import os
import select
import socket
import sys
import time

RENDEZVOUS_PORT = 6667

default_logfile = '/var/log/rendezd.log'
default_pidfile = '/var/run/rendezd.pid'
default_peer_ip = None
default_app_port = 1337


def addr_str(a):
    return '{}:{}'.format(a[0], a[1])


def send_addr(sock, peer_addr, dest):
    sock.sendto(addr_str(peer_addr), dest)


def run():
    sessions = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('', RENDEZVOUS_PORT)
    sock.bind(server_address)

    try:
        while True:
            session_name, sender_addr = sock.recvfrom(64)
            if args.peer_ip is None:
                if session_name in sessions:
                    # Recognized, so send addresses to the peers
                    logger.info('{}: complete -- {} <--> {}'
                                .format(session_name,
                                        addr_str(sessions[session_name]),
                                        addr_str(sender_addr)))
                    send_addr(sock, sessions[session_name], sender_addr)
                    send_addr(sock, sender_addr, sessions[session_name])
                    del sessions[session_name]
                else:
                    # Create new session if unrecognized, storing the sender's
                    # address as the initiator.
                    logger.info('{}: {} <--> [waiting for peer]'
                                .format(session_name, addr_str(sender_addr)))
                    sessions[session_name] = sender_addr
            else:
                logger.info('{}: complete -- {} <--> {} (this host), '
                            'this host is the peer.'
                            .format(session_name, addr_str(sender_addr),
                                    addr_str((args.peer_ip,
                                              args.application_port))))
                send_addr(sock, (args.peer_ip, args.application_port),
                          sender_addr)
                if args.test_peer:
                    fqdn = socket.getfqdn()
                    for _ in xrange(5):
                        sock.sendto(fqdn, (sender_addr[0],
                                           int(sender_addr[1])))
                        r, w, e = select.select([sock], [], [], 2.0)
                        if len(r) == 1:
                            msg, peer_addr = sock.recvfrom(12)
                            logger.info('{}: peer sent "{}"'
                                        .format(session_name, msg))
                        time.sleep(2)

    except (KeyboardInterrupt, SystemExit):
        logger.info('shutting down')

parser = argparse.ArgumentParser(
    description='Receive UDP hole punching packets and reply, '
    'coordinating peers.')

parser.add_argument('--log-file', '-l', default=default_logfile,
                    help=('Name of output log file for daemon mode '
                          '(default: {})'.format(default_logfile)))

parser.add_argument('--pid-file', '-p', default=default_pidfile,
                    help=('Name of PID file for daemon mode (default: {})'
                          .format(default_pidfile)))

parser.add_argument('--foreground', '-f', action='store_true',
                    help='run in foreground (default: run as daemon)')

parser.add_argument('--peer-ip', '-i', default=default_peer_ip,
                    help='Address to return as the remote peer (default: {}, '
                    'meaning wait for a second peer before with the same '
                    'session ID before responding.)'.format(default_peer_ip))

parser.add_argument('--application-port', '-a', type=int,
                    default=default_app_port,
                    help='application port (default: {})'
                    .format(default_app_port))

parser.add_argument('--test-peer', '-t', action='store_true',
                    help='Transmit application packets to peer, listen for '
                    'packets from peer (default: False)')

args = parser.parse_args()

logger = logging.getLogger('rendezd')
level = logging.INFO
logger.setLevel(level)
formatter = logging.Formatter('%(asctime)s - %(name)s - '
                              '%(levelname)s - %(message)s')
try:
    log_handler = (logging.StreamHandler() if args.foreground
                   else logging.FileHandler(args.log_file))
except Exception as e:
    print e
    sys.exit(1)

log_handler.setLevel(level)
log_handler.setFormatter(formatter)
logger.addHandler(log_handler)

if args.foreground:
    run()
else:
    with daemon.DaemonContext(
            files_preserve=[log_handler.stream.fileno()]):
        with open(args.pid_file, 'w') as pidfile:
            print >>pidfile, os.getpid()
        run()
        os.remove(args.pid_file)
