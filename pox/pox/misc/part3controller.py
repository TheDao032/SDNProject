# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

class Part3Controller (object):
  """
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    #use the dpid to figure out what switch is being created
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)

  def s1_setup(self):
    #put switch 1 rules here
    self.flood()
    # show never reach here
    self.drop()

  def s2_setup(self):
    #put switch 2 rules here
    self.flood()
    # show never reach here
    self.drop()

  def s3_setup(self):
    #put switch 3 rules here
    self.flood()
    # show never reach here
    self.drop()

  def cores21_setup(self):
    # put core switch rules here

    # black list
    # block all ICMP traffic from untrusted host
    fm_icmp_block = of.ofp_flow_mod()
    fm_icmp_block.priority = 10 # highest priority
    fm_icmp_block.match.dl_type = 0x0800 # IPv4
    fm_icmp_block.match.nw_proto = 1 # ICMP
    fm_icmp_block.match.nw_src = IPS["hnotrust"][0] # from untrusted host
    # no actions added
    self.connection.send(fm_icmp_block)

    # block all traffic from untrusted host to datacenter
    # block all ICMP traffic from untrusted host
    fm_ipv4_block = of.ofp_flow_mod()
    fm_ipv4_block.priority = 9 # a reasonable priority
    fm_ipv4_block.match.dl_type = 0x0800 # IPv4
    fm_ipv4_block.match.nw_src = IPS["hnotrust"][0] # from untrusted host
    fm_ipv4_block.match.nw_dst = IPS["serv1"][0] # to datacenter
    # no actions added
    self.connection.send(fm_ipv4_block)

    # actual routing
    # host 10
    fm_route_port_1 = of.ofp_flow_mod()
    fm_route_port_1.priority = 8
    fm_route_port_1.match.dl_type = 0x0800 # IPv4
    fm_route_port_1.match.nw_dst = IPS["h10"][0] # to host 1
    fm_route_port_1.actions.append(of.ofp_action_output(port = 1)) # send it out through port 1
    self.connection.send(fm_route_port_1)

    # host 20
    fm_route_port_2 = of.ofp_flow_mod()
    fm_route_port_2.priority = 8
    fm_route_port_2.match.dl_type = 0x0800 # IPv4
    fm_route_port_2.match.nw_dst = IPS["h20"][0] # to host 2
    fm_route_port_2.actions.append(of.ofp_action_output(port = 2)) # send it out through port 1
    self.connection.send(fm_route_port_2)

    # host 30
    fm_route_port_3 = of.ofp_flow_mod()
    fm_route_port_3.priority = 8
    fm_route_port_3.match.dl_type = 0x0800 # IPv4
    fm_route_port_3.match.nw_dst = IPS["h30"][0] # to host 3
    fm_route_port_3.actions.append(of.ofp_action_output(port = 3)) # send it out through port 3
    self.connection.send(fm_route_port_3)

    # datacenter
    fm_route_port_dc = of.ofp_flow_mod()
    fm_route_port_dc.priority = 8
    fm_route_port_dc.match.dl_type = 0x0800 # IPvdc
    fm_route_port_dc.match.nw_dst = IPS["serv1"][0] # to host dc
    fm_route_port_dc.actions.append(of.ofp_action_output(port = 4)) # send it out through port 4
    self.connection.send(fm_route_port_dc)

    # out to the Internet
    fm_route_port_5 = of.ofp_flow_mod()
    fm_route_port_5.priority = 8
    fm_route_port_5.match.dl_type = 0x0800 # IPv4
    fm_route_port_5.actions.append(of.ofp_action_output(port = 5)) # send it out through port 5
    self.connection.send(fm_route_port_5)

    # handle ARP and other non-IP traffic
    self.flood()
    # show never reach here
    self.drop()

  def dcs31_setup(self):
    #put datacenter switch rules here
    # flood
    self.flood()
    # show never reach here
    self.drop()

  # flood the message to all ports: for s1 - s3, dcs
  def flood(self):
    fm = of.ofp_flow_mod()
    fm.priority = 1 # a slightly higher priority than drop
    fm.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(fm)

  def drop(self):
    # drop other packets
    fm_drop = of.ofp_flow_mod()
    # ICMP
    fm_drop.priority = 0 # a low priority
    # flood all ports
    self.connection.send(fm_drop)

  #used in part 4 to handle individual ARP packets
  #not needed for part 3 (USE RULES!)
  #causes the switch to output packet_in on out_port
  def resend_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part3Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)

