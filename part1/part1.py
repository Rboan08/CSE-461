#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI


class part1_topo(Topo):
    def build(self):
        # switch1 = self.addSwitch('switchname')
        # host1 = self.addHost('hostname')
        # self.addLink(hostname,switchname)
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')

        switch1 = self.addSwitch('s1')
	
        self.addLink('h1', 's1')
        self.addLink('h2', 's1')
        self.addLink('h3', 's1')
        self.addLink('h4', 's1')


topos = {"part1": part1_topo}

if __name__ == "__main__":
    t = part1_topo()
    net = Mininet(topo=t, controller=None)
    net.start()
    CLI(net)
    net.stop()
