# Copyright 2017 Jarrod N. Bakker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from mininet.cli import CLI
from mininet.log import lg
from mininet.log import setLogLevel
import mininet.node
from mininet.link import Link
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


__author__ = "Jarrod N. Bakker"
__status__ = "Development"


# Explicitly define the names and other details of each node in our
# test network.
_NODES = {"mgmts1": {"name": "mgmts1",
                     "mgmt_mac_c0": "00:00:00:01:cc:01",
                     "mgmt_mac_h1": "00:00:00:01:00:11",
                     "mgmt_mac_h2": "00:00:00:01:00:12"},
          "dps1": {"name": "dps1", "cp_mac": "00:00:00:02:cc:50",
                   "cp_ip": "192.168.0.50",
                   "dp_mac_h1": "00:00:00:00:11:51",
                   "dp_mac_h2": "00:00:00:00:12:52", "inband": False,
                   "protocols": "OpenFlow13"},
          "controller": {"name": "c0", "cp_mac": "00:00:00:02:cc:01",
                         "cp_ip": "192.168.0.1", "of_port": 6653,
                         "mgmt_mac": "00:00:00:01:cc:01",
                         "mgmt_ip": "172.16.0.1"},
          "host1": {"name": "h1", "mgmt_mac": "00:00:00:01:00:11",
                    "mgmt_ip": "172.16.0.11",
                    "dp_mac": "00:00:00:00:00:11", "dp_ip": "10.0.0.11"},
          "host2": {"name": "h2", "mgmt_mac": "00:00:00:01:00:12",
                    "mgmt_ip": "172.16.0.12",
                    "dp_mac": "00:00:00:00:00:12", "dp_ip": "10.0.0.12"}}


def get_node_configs():
    """Return dictionaries containing the configuration details of all
    hosts.

    :return: A tuple of the dictionaries from each host,
    """
    return (_NODES["mgmts1"], _NODES["dps1"], _NODES["controller"],
            _NODES["host1"], _NODES["host2"])


class BasicNetwork(Topo):
    """A basic network: a single switch, controller and two hosts.
    """

    def build(self):
        """Build the basic topology.
        """
        # Get the configuration details of the nodes
        mgmts1_conf, dps1_conf, c0_conf, h1_conf, h2_conf = \
            get_node_configs()

        # Create a switch that will connect the control plane together.
        self.addSwitch(mgmts1_conf["name"])

        # Create an OpenFlow switch running OVS
        dps1_opts = {"inband": dps1_conf["inband"],
                     "protocols": dps1_conf["protocols"]}
        self.addSwitch(dps1_conf["name"], opts=dps1_opts)

        # Create a host that the controller will run on
        self.addHost(c0_conf["name"])

        # Create two hosts
        self.addHost(h1_conf["name"])
        self.addHost(h2_conf["name"])


def configure_links(net):
    """Configure the links and interfaces in the network.

    :param net: A Mininet object with a virtual network.
    """
    # Get the configuration details of the nodes
    mgmts1_conf, dps1_conf, c0_conf, h1_conf, h2_conf = \
        get_node_configs()

    # Get the node objects for the switches
    mgmts1 = net.getNodeByName(mgmts1_conf["name"])
    dps1 = net.getNodeByName(dps1_conf["name"])

    # Create links for the controller
    c0 = net.getNodeByName(c0_conf["name"])
    cp_link = Link(c0, dps1, port1=0, port2=0,
                   addr1=c0_conf["cp_mac"],
                   addr2=dps1_conf["cp_mac"])
    c0.setIP(c0_conf["cp_ip"], intf=cp_link.intf1)
    c0_if_mgmt = Link(c0, mgmts1, port1=1, port2=0,
                      addr1=c0_conf["mgmt_mac"],
                      addr2=mgmts1_conf["mgmt_mac_c0"]).intf1
    c0.setIP(c0_conf["mgmt_ip"], intf=c0_if_mgmt)

    # Set the OpenFlow switch's control plane IP address
    dps1.setIP(dps1_conf["cp_ip"], intf=cp_link.intf2)

    # Create links for host 1
    h1 = net.getNodeByName(h1_conf["name"])
    h1_if_dp = Link(h1, dps1, port1=0, port2=1,
                    addr1=h1_conf["dp_mac"],
                    addr2=dps1_conf["dp_mac_h1"]).intf1
    h1.setIP(h1_conf["dp_ip"], intf=h1_if_dp)
    h1_if_mgmt = Link(h1, mgmts1, port1=1, port2=1,
                      addr1=h1_conf["mgmt_mac"],
                      addr2=mgmts1_conf["mgmt_mac_h1"]).intf1
    h1.setIP(h1_conf["mgmt_ip"], intf=h1_if_mgmt)

    # Create links for host 2
    h2 = net.getNodeByName(h2_conf["name"])
    h2_if_dp = Link(h2, dps1, port1=0, port2=2,
                    addr1=h2_conf["dp_mac"],
                    addr2=dps1_conf["dp_mac_h2"]).intf1
    h2.setIP(h2_conf["dp_ip"], intf=h2_if_dp)
    h2_if_mgmt = Link(h2, mgmts1, port1=1, port2=2,
                      addr1=h2_conf["mgmt_mac"],
                      addr2=mgmts1_conf["mgmt_mac_h2"]).intf1
    h2.setIP(h2_conf["mgmt_ip"], intf=h2_if_mgmt)


if __name__ == "__main__":
    setLogLevel("info")
    topo = BasicNetwork()
    net = Mininet(topo, build=False, controller=None)
    net.build()
    configure_links(net)
    net.start()
    lg.info("*** Dumping host interface connections\n")
    dumpNodeConnections(net.hosts)
    lg.info("*** Dumping switch interface connections\n")
    dumpNodeConnections(net.switches)
    CLI(net)
    net.stop()