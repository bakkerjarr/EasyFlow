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
from mininet.node import OVSSwitch
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


__author__ = "Jarrod N. Bakker"
__status__ = "Development"


# Global variables #
_NETWORK = None  # Object to hold the Mininet network

# Explicitly define the names and other details of each node in our
# test network.
#
# MAC address convention. Note that FF is not used as a value to avoid
# the possibility of forming the broadcast MAC address.
#
# 00:<network>:<host type>:<switch number>:<connected
# host type>:<host number>
#
# network: 00 (data-plane), 11 (control-plane), 22 (management)
# host type: 00 ('normal' host), 11 (controller), 22 (switch) (used to
#            indicate what kind of host this host is)
# switch number: 00-FE (used to uniquely identify switches, this is set
#                to 00 when host device type is not 22)
# connected host type: 00 ('normal' host), 11 (controller),
#                      22 (switch) (indicates what kind of host this
#                      host is connected to)
# host number: 00-FE (used to uniquely identify a host when the host
#              device type is not 22, else it indicates what host is
#              connected to this port)
_NODES = {"mgmts1": {"name": "mgmts1",
                     "mgmt_mac_c0": "00:22:22:01:11:01",
                     "mgmt_mac_h1": "00:22:22:01:01:11",
                     "mgmt_mac_h2": "00:22:22:01:01:12"},
          "dps1": {"name": "dps1", "cp_mac": "00:11:22:01:11:01",
                   "cp_ip": "192.168.0.50/24",
                   "dp_mac_h1": "00:00:22:01:00:11",
                   "dp_mac_h2": "00:00:22:01:00:12", "inband": False,
                   "protocols": "OpenFlow13"},
          "controller": {"name": "c0", "cp_mac": "00:11:11:00:22:01",
                         "cp_ip": "192.168.0.1/24", "of_port": 6653,
                         "mgmt_mac": "00:22:11:00:22:01",
                         "mgmt_ip": "10.0.0.1/16"},
          "host1": {"name": "h1", "mgmt_mac": "00:22:00:00:22:11",
                    "mgmt_ip": "10.0.1.11/16",
                    "dp_mac": "00:00:00:00:22:11",
                    "dp_ip": "172.16.0.11/24"},
          "host2": {"name": "h2", "mgmt_mac": "00:22:00:00:22:12",
                    "mgmt_ip": "10.0.1.12/16",
                    "dp_mac": "00:00:00:00:22:12",
                    "dp_ip": "172.16.0.12/24"}}


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

        # Create a switch that will connect the management network
        # together (currently 10.0.0.0/16).
        self.addSwitch(mgmts1_conf["name"])

        # Create an OpenFlow switch running OVS for the data-plane
        # network (currently 172.16.0.0/24).
        dps1_opts = {"inband": dps1_conf["inband"],
                     "protocols": dps1_conf["protocols"]}
        self.addSwitch(dps1_conf["name"], listenPort=c0_conf["of_port"],
                       opts=dps1_opts)

        # Create a host that the controller will run on
        self.addHost(c0_conf["name"])

        # Create two hosts
        self.addHost(h1_conf["name"])
        self.addHost(h2_conf["name"])


def _configure_links():
    """Configure the links and interfaces in the network.

    Note: Port 0 (i.e. eth0) on an Open vSwitch switch is not part of
    the switch bridge used to support communication between multiple
    hosts. Therefore switch port 0 is only used to connect interfaces
    in an OpenFlow controller-switch relationship.
    """
    lg.info("***Configuring interfaces on all nodes\n")
    # Get the configuration details of the nodes
    mgmts1_conf, dps1_conf, c0_conf, h1_conf, h2_conf = \
        get_node_configs()

    # Get the node objects for the switches
    mgmts1 = _NETWORK.getNodeByName(mgmts1_conf["name"])
    dps1 = _NETWORK.getNodeByName(dps1_conf["name"])

    # Create links for the controller
    c0 = _NETWORK.getNodeByName(c0_conf["name"])
    cp_link = Link(c0, dps1, port1=0, port2=0,
                   addr1=c0_conf["cp_mac"],
                   addr2=dps1_conf["cp_mac"])
    c0.setIP(c0_conf["cp_ip"], intf=cp_link.intf1)
    c0_if_mgmt = Link(c0, mgmts1, port1=1, port2=1,
                      addr1=c0_conf["mgmt_mac"],
                      addr2=mgmts1_conf["mgmt_mac_c0"]).intf1
    c0.setIP(c0_conf["mgmt_ip"], intf=c0_if_mgmt)

    # Set the OpenFlow switch's control-plane IP address
    dps1.setIP(dps1_conf["cp_ip"], intf=cp_link.intf2)

    # Create links for host 1
    h1 = _NETWORK.getNodeByName(h1_conf["name"])
    h1_if_dp = Link(h1, dps1, port1=0, port2=1,
                    addr1=h1_conf["dp_mac"],
                    addr2=dps1_conf["dp_mac_h1"]).intf1
    h1.setIP(h1_conf["dp_ip"], intf=h1_if_dp)
    h1_if_mgmt = Link(h1, mgmts1, port1=1, port2=2,
                      addr1=h1_conf["mgmt_mac"],
                      addr2=mgmts1_conf["mgmt_mac_h1"]).intf1
    h1.setIP(h1_conf["mgmt_ip"], intf=h1_if_mgmt)

    # Create links for host 2
    h2 = _NETWORK.getNodeByName(h2_conf["name"])
    h2_if_dp = Link(h2, dps1, port1=0, port2=2,
                    addr1=h2_conf["dp_mac"],
                    addr2=dps1_conf["dp_mac_h2"]).intf1
    h2.setIP(h2_conf["dp_ip"], intf=h2_if_dp)
    h2_if_mgmt = Link(h2, mgmts1, port1=1, port2=3,
                      addr1=h2_conf["mgmt_mac"],
                      addr2=mgmts1_conf["mgmt_mac_h2"]).intf1
    h2.setIP(h2_conf["mgmt_ip"], intf=h2_if_mgmt)


def _config_mgmts1():
    """Configure the management network switch to behave like a
    standard layer 2 Ethernet switch.
    """
    # Get the configuration details of the nodes
    mgmts1_conf, dps1_conf, c0_conf, h1_conf, h2_conf = \
        get_node_configs()

    # Get the node object for the management network switch
    mgmts1 = _NETWORK.getNodeByName(mgmts1_conf["name"])

    # Create a flow table entry instructing the management network
    # switch to behave like a standard layer 2 Ethernet switch.
    # Because of the way that Mininet work, our switch with the name
    # 'mgmts1' is really just an Open vSwitch bridge. This is why
    # 'mgmts1' is found in bridge interface position in the command.
    lg.info("*** Disabling OpenFlow and configuring layer 2 Ethernet "
            "switch behaviour on switch %s\n" % (mgmts1_conf["name"]))
    mgmts1.cmd("ovs-ofctl add-flow mgmts1 action=normal")


def _kill_ryu():
    """Kill the ryu-manager process running on the controller (c0).
    """
    # Get the configuration details of the nodes
    mgmts1_conf, dps1_conf, c0_conf, h1_conf, h2_conf = \
        get_node_configs()

    cmd = "pkill \"ryu-manager\""
    c0 = _NETWORK.getNodeByName(c0_conf["name"])
    lg.info("*** Terminating the Ryu application on %s\n" % (c0_conf["name"]))
    c0.cmd(cmd)


def network_start_dataplane(ryu_app_path):
    """Manually start the OpenFlow control-plane session between the
    controller (c0) and the data-plane switch (dps1).

    :param ryu_app_path: Path to a Ryu application to be run.
    """
    # Get the configuration details of the nodes
    mgmts1_conf, dps1_conf, c0_conf, h1_conf, h2_conf = \
        get_node_configs()

    # Start a Ryu application on c0.
    cmd = "ryu-manager --verbose --ofp-tcp-listen-port %d %s &" % (
                                        c0_conf["of_port"], ryu_app_path)
    c0 = _NETWORK.getNodeByName(c0_conf["name"])
    lg.info("*** Starting Ryu application %s on %s\n" % (ryu_app_path,
                                                         c0_conf["name"]))
    c0.cmd(cmd)

    # Manually configure dps1 to connect to c0.
    c0_ip = c0_conf["cp_ip"].split("/")[0]  # Need to strip the mask
    cmd = "ovs-vsctl set-controller %s tcp:%s:%d" % (dps1_conf["name"],
                                                     c0_ip,
                                                     c0_conf["of_port"])
    dps1 = _NETWORK.getNodeByName(dps1_conf["name"])
    lg.info("*** Manually starting the OF control-plane session "
            "between %s and %s\n" % (c0_conf["name"], dps1_conf["name"]))
    dps1.cmd(cmd)


if __name__ == "__main__":
    setLogLevel("info")
    topo = BasicNetwork()
    _NETWORK = Mininet(topo, build=False, controller=None,
                       switch=OVSSwitch)
    _NETWORK.build()
    _configure_links()
    _NETWORK.start()
    _config_mgmts1()
    lg.info("*** Dumping host interface connections\n")
    dumpNodeConnections(_NETWORK.hosts)
    lg.info("*** Dumping switch interface connections\n")
    dumpNodeConnections(_NETWORK.switches)

    # Start the OF control-plane session
    ryu_app = "/usr/local/lib/python3.5/dist-packages/ryu/app/" \
              "simple_switch_13.py"
    network_start_dataplane(ryu_app)

    # Start the interactive command-line.
    CLI(_NETWORK)
    _kill_ryu()
    _NETWORK.stop()
