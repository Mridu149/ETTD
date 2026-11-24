#!/usr/bin/env python3
"""Campus network lab for the encrypted-traffic project.

Run:   sudo python3 campus_lab.py --benign
In the mininet> prompt:
    capture start captures/benign_01.pcap
    capture stop
"""
import argparse
import os
import subprocess
import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSBridge

HERE = os.path.dirname(os.path.abspath(__file__))
PCS = ['pc0', 'pc1', 'pc2', 'pc3', 'pc4', 'pc5', 'pc6', 'pc7']

# department -> (subnet number, [(host name, last octet)])   matches the Packet Tracer diagram
CAMPUS = {
    'civil': (1, [('pc0', 10)]),
    'food':  (2, [('pc1', 10)]),
    'mech':  (3, [('pc2', 10)]),
    'dean':  (4, [('pc3', 10), ('srv1', 20)]),
    'cs':    (5, [('pc4', 10), ('pc6', 11), ('pc7', 12), ('srv0', 20)]),
    'elec':  (6, [('pc5', 10)]),
}

# "internet" side: name -> last octet in 203.0.113.0/24
INTERNET = {'srv2': 10,   # web server
            'srv3': 11,   # DNS server
            'srv4': 12}   # fake C2 server


class LinuxRouter(Node):
    """A host that forwards packets between its interfaces."""
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()


def build():
    net = Mininet(controller=None, switch=OVSBridge, autoSetMacs=True)

    cr = net.addHost('cr', cls=LinuxRouter, ip=None)   # campus router + L3 switch
    ir = net.addHost('ir', cls=LinuxRouter, ip=None)   # internet router

    # uplink between the routers: this is where traffic is captured
    net.addLink(cr, ir,
                intfName1='cr-up', intfName2='ir-campus',
                params1={'ip': '172.16.0.1/30'},
                params2={'ip': '172.16.0.2/30'})

    for i, (dept, (n, hosts)) in enumerate(CAMPUS.items(), start=1):
        sw = net.addSwitch(f's_{dept}', dpid=f'{i:016x}')
        gw = f'10.0.{n}.1'
        net.addLink(sw, cr, intfName2=f'cr-{dept}', params2={'ip': f'{gw}/24'})
        for name, octet in hosts:
            h = net.addHost(name, ip=f'10.0.{n}.{octet}/24',
                            defaultRoute=f'via {gw}')
            net.addLink(h, sw)

    s_net = net.addSwitch('s_net', dpid=f'{99:016x}')
    net.addLink(s_net, ir, intfName2='ir-net', params2={'ip': '203.0.113.1/24'})
    for name, octet in INTERNET.items():
        h = net.addHost(name, ip=f'203.0.113.{octet}/24',
                        defaultRoute='via 203.0.113.1')
        net.addLink(h, s_net)

    return net, cr, ir


def start_services(net):
    net.get('srv3').cmd(
        'dnsmasq --no-daemon --no-resolv --no-hosts --bind-interfaces '
        '--listen-address=203.0.113.11 --pid-file=/tmp/dnsmasq-srv3.pid '
        '--address=/lab/203.0.113.10 --address=/c2.lab/203.0.113.12 '
        '--log-queries --log-facility=/tmp/srv3-dns.log > /tmp/srv3.out 2>&1 &')
    for host, ip in (('srv2', '203.0.113.10'), ('srv4', '203.0.113.12')):
        net.get(host).cmd(
            f'python3 {HERE}/https_server.py {ip} 443 {HERE}/certs {HERE}/www '
            f'> /tmp/{host}.log 2>&1 &')


def start_benign(net):
    for name in PCS:
        net.get(name).cmd(f'{HERE}/gen_benign.sh > /tmp/benign_{name}.log 2>&1 &')


def stop_everything():
    for pattern in ('https_server.py', 'gen_benign.sh', 'dnsmasq --no-daemon'):
        subprocess.call(['pkill', '-f', pattern])


def give_file_to_user(path):
    """Captures are written by root; hand them back to the person who ran sudo."""
    uid, gid = os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')
    if uid and gid and os.path.exists(path):
        os.chown(path, int(uid), int(gid))


class LabCLI(CLI):
    """Mininet prompt with an extra 'capture' command."""

    def do_capture(self, line):
        """capture start <file.pcap> | capture stop  -- record the uplink (cr-up)"""
        args = line.split()
        cr = self.mn.get('cr')
        if len(args) == 2 and args[0] == 'start':
            path = os.path.abspath(args[1])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            cr.cmd(f'tcpdump -Z root -U -i cr-up -w {path} > /tmp/capture.out 2>&1 &')
            self.capture_path = path
            print(f'capturing on cr-up to {path}')
        elif args == ['stop']:
            cr.cmd('pkill tcpdump')
            time.sleep(1)
            path = getattr(self, 'capture_path', None)
            if path:
                give_file_to_user(path)
                print(f'capture saved: {path}')
        else:
            print('usage: capture start <file.pcap> | capture stop')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--benign', action='store_true',
                        help='start background benign traffic on all PCs')
    args = parser.parse_args()

    setLogLevel('info')
    net, cr, ir = build()
    net.start()
    cr.cmd('ip route add default via 172.16.0.2')
    ir.cmd('ip route add 10.0.0.0/16 via 172.16.0.1')
    start_services(net)
    if args.benign:
        start_benign(net)
    print('\n*** Lab ready. Try:  pc0 ping -c 2 srv2   |   pingall   |   capture start captures/x.pcap')
    LabCLI(net)
    stop_everything()
    net.stop()
