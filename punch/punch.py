#!/usr/bin/env python

import argparse
import select
import socket
import time

RENDEZVOUS_PORT = 6667

default_app_port = 1337
default_server = '127.0.0.1'
fqdn = socket.getfqdn()
default_session_name = fqdn

parser = argparse.ArgumentParser(
    description='Punch a hole for UDP, receive response packets.')

parser.add_argument('--rendezvous-server', '-r', default=default_server,
                    help='address of server (default: {})'
                    .format(default_server))

parser.add_argument('--application-port', '-a', type=int,
                    default=default_app_port,
                    help='application port (default: {})'
                    .format(default_app_port))

parser.add_argument('--session-name', '-s',
                    default=default_session_name,
                    help=('Session name (default: {})'
                          .format(default_session_name)))

parser.add_argument('--test-peer', '-t', action='store_true',
                    help='Transmit application packets to peer, listen for '
                    'packets from peer (default: False)')

args = parser.parse_args()

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('', args.application_port)
    sock.bind(server_address)

    sock.sendto(args.session_name, (args.rendezvous_server, RENDEZVOUS_PORT))
    peer_addr_str, server_addr = sock.recvfrom(64)
    print('peer: {}'.format(peer_addr_str))
    peer_addr = peer_addr_str.split(':')
    if args.test_peer:
        for _ in xrange(5):
            sock.sendto(fqdn, (peer_addr[0], int(peer_addr[1])))
            r, w, e = select.select([sock], [], [], 2.0)
            if len(r) == 1:
                msg, peer_addr = sock.recvfrom(12)
                print('peer sent "{}"'.format(msg))
            time.sleep(2)

except (KeyboardInterrupt, SystemExit):
    print('shutting down')
