# An example of a firewall for POX
# Blocking ICMP requests to the MAC address(es) 
# listed in the 'rules' list.
# Mainteiner me@sergeel.space

from pox.core import core
import pox.lib.packet as pkt

#rules = [['00:00:00:00:00:01'], ['00:00:00:00:00:02']]
rules = [['00:00:00:00:00:01']]

def sdn_firewall (event):
  if (event.parsed.type == 2048): # TYPE == IP Packet
    icmp = pkt.icmp()
    packet = event.parsed
    icmp.type = packet.find("icmp").type
    for rule in rules:
      if(event.parsed.dst == rule[0] and icmp.type == 8 ): # TYPE == ICMP echo request
        core.getLogger("firewall").debug(
          "Blocked ICMP echo request to %s ", event.parsed.dst)
        event.halt = True

def launch ():
  # Listen to packet events
  core.openflow.addListenerByName("PacketIn", sdn_firewall)
