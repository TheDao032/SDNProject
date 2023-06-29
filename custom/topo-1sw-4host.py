"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- host
              |
   host ----- | ----- host
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo


class MyTopo2(Topo):
    "Simple topology example."

    def build(self):
        "Create custom topo."

        # Add hosts and switches
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')

        switch = self.addSwitch('s1')

        # Add links
        self.addLink(host1, switch)
        self.addLink(host2, switch)
        self.addLink(host3, switch)
        self.addLink(host4, switch)


topos = {'mytopo2': (lambda: MyTopo2())}
