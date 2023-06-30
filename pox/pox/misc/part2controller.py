# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

all_ports = of.OFPP_FLOOD
table = {}


class Firewall(object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # add switch rules here

    def allow_packet(self, event, packet):
        table[(event.connection,packet.src)] = event.port

        dst_port = table.get((event.connection,packet.dst))

        if dst_port is None:
            # We don't know where the destination is yet.  So, we'll just
            # send the packet out all ports (except the one it came in on!)
            # and hope the destination is out there somewhere. :)
            msg = of.ofp_packet_out(data = event.ofp)
            msg.actions.append(of.ofp_action_output(port = all_ports))
            event.connection.send(msg)
        else:
            # Since we know the switch ports for both the source and dest
            # MACs, we can install rules for both directions.
            msg = of.ofp_flow_mod()
            msg.match.dl_dst = packet.src
            msg.match.dl_src = packet.dst
            msg.actions.append(of.ofp_action_output(port = event.port))
            event.connection.send(msg)

            # This is the packet that just came in -- we want to
            # install the rule and also resend the packet.
            msg = of.ofp_flow_mod()
            msg.data = event.ofp # Forward the incoming packet
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.actions.append(of.ofp_action_output(port = dst_port))
            event.connection.send(msg)

            log.debug("Installing %s <-> %s" % (packet.src, packet.dst))

    def drop_packet(self, event):
        # Create a flow mod message to drop the packet
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed)
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print("Unhandled packet :" + str(packet.dump()))
        # print("packet_in :" + str(packet_in))
        # Allow all ARP traffic
        if packet.type == packet.ARP_TYPE:
            self.allow_packet(event, packet)
            return

        # Allow ICMP traffic
        if packet.type == packet.IP_TYPE and packet.find('icmp'):
            self.allow_packet(event)
            return

        # Drop all other traffic
        self.drop_packet(event)


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
