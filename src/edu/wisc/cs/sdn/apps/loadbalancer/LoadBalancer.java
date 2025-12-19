package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.l3routing.IL3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application
    private IL3Routing l3RoutingApp;
    
    // Switch table in which rules should be installed
    private byte table;

    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Parse load balancer instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(IL3Routing.class);
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param switchId for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		// Install rules for each virtual IP
		for (Integer virtualIP : this.instances.keySet())
		{
			// TCP packets to VIP -> send to controller
			OFMatch matchTcp = new OFMatch();
			matchTcp.setDataLayerType(Ethernet.TYPE_IPv4);
			matchTcp.setNetworkProtocol(IPv4.PROTOCOL_TCP);
			matchTcp.setNetworkDestination(virtualIP);
			
			OFAction actionToController = new OFActionOutput(OFPort.OFPP_CONTROLLER);
			OFInstruction instrTcp = new OFInstructionApplyActions(Arrays.asList(actionToController));
			
			SwitchCommands.installRule(sw, this.table, 
					(short)(SwitchCommands.DEFAULT_PRIORITY + 1),
					matchTcp, Arrays.asList(instrTcp));
			
			// ARP for VIP -> send to controller
			OFMatch matchArp = new OFMatch();
			matchArp.setDataLayerType(Ethernet.TYPE_ARP);
			matchArp.setNetworkDestination(virtualIP);
			
			OFInstruction instrArp = new OFInstructionApplyActions(Arrays.asList(actionToController));
			
			SwitchCommands.installRule(sw, this.table,
					(short)(SwitchCommands.DEFAULT_PRIORITY + 1),
					matchArp, Arrays.asList(instrArp));
		}
		
		// Default: send to L3 routing table
		OFMatch matchDefault = new OFMatch();
		OFInstruction instrGotoTable = new OFInstructionGotoTable(this.l3RoutingApp.getTable());
		
		SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY,
				matchDefault, Arrays.asList(instrGotoTable));
	}
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);
		
		// Handle ARP requests for virtual IPs
		if (ethPkt.getEtherType() == Ethernet.TYPE_ARP)
		{
			ARP arpPkt = (ARP)ethPkt.getPayload();
			
			// Only handle ARP requests
			if (arpPkt.getOpCode() == ARP.OP_REQUEST)
			{
			int targetIP = IPv4.toIPv4Address(arpPkt.getTargetProtocolAddress());
			
				// Check if this is for one of our virtual IPs
				if (this.instances.containsKey(targetIP))
			{
				LoadBalancerInstance instance = this.instances.get(targetIP);
				
					// Construct ARP reply
				ARP arpReply = new ARP();
				arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
				arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
				arpReply.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
				arpReply.setProtocolAddressLength((byte)4);
				arpReply.setOpCode(ARP.OP_REPLY);
				arpReply.setSenderHardwareAddress(instance.getVirtualMAC());
				arpReply.setSenderProtocolAddress(targetIP);
				arpReply.setTargetHardwareAddress(arpPkt.getSenderHardwareAddress());
				arpReply.setTargetProtocolAddress(arpPkt.getSenderProtocolAddress());
				
					// Construct Ethernet frame
				Ethernet ethReply = new Ethernet();
				ethReply.setEtherType(Ethernet.TYPE_ARP);
				ethReply.setSourceMACAddress(instance.getVirtualMAC());
				ethReply.setDestinationMACAddress(ethPkt.getSourceMACAddress());
				ethReply.setPayload(arpReply);
				
					// Send the ARP reply
				SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), ethReply);
					
				return Command.STOP;
			}
		}
		}
		// Handle IPv4 packets (TCP)
		else if (ethPkt.getEtherType() == Ethernet.TYPE_IPv4)
		{
			IPv4 ipPkt = (IPv4)ethPkt.getPayload();
			
			// Only handle TCP
			if (ipPkt.getProtocol() == IPv4.PROTOCOL_TCP)
			{
				TCP tcpPkt = (TCP)ipPkt.getPayload();
				int dstIP = ipPkt.getDestinationAddress();
				
				// Check if destination is a virtual IP
				if (this.instances.containsKey(dstIP))
				{
					LoadBalancerInstance instance = this.instances.get(dstIP);
					
					// Check if this is a TCP SYN
					if (tcpPkt.getFlags() == TCP_FLAG_SYN)
					{
						// Select next host in round-robin
						int hostIP = instance.getNextHostIP();
						byte[] hostMAC = getHostMACAddress(hostIP);
						
						if (hostMAC == null)
						{
							log.warn("Could not find MAC for host " + IPv4.fromIPv4Address(hostIP));
							return Command.CONTINUE;
						}
						
						// Install connection-specific rules on this switch
						// Rule 1: Client -> Server (rewrite destination IP and MAC)
						OFMatch matchClientToServer = new OFMatch();
						matchClientToServer.setDataLayerType(Ethernet.TYPE_IPv4);
						matchClientToServer.setNetworkProtocol(IPv4.PROTOCOL_TCP);
						matchClientToServer.setNetworkSource(ipPkt.getSourceAddress());
						matchClientToServer.setNetworkDestination(dstIP);
						matchClientToServer.setTransportSource(tcpPkt.getSourcePort());
						matchClientToServer.setTransportDestination(tcpPkt.getDestinationPort());
						
						ArrayList<OFAction> actionsC2S = new ArrayList<OFAction>();
						actionsC2S.add(new OFActionSetField(OFOXMFieldType.ETH_DST, hostMAC));
						actionsC2S.add(new OFActionSetField(OFOXMFieldType.IPV4_DST, hostIP));
						
						ArrayList<OFInstruction> instructionsC2S = new ArrayList<OFInstruction>();
						instructionsC2S.add(new OFInstructionApplyActions(actionsC2S));
						instructionsC2S.add(new OFInstructionGotoTable(this.l3RoutingApp.getTable()));
						
						SwitchCommands.installRule(sw, this.table,
								(short)(SwitchCommands.DEFAULT_PRIORITY + 2),
								matchClientToServer, instructionsC2S,
								SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);
						
						// Rule 2: Server -> Client (rewrite source IP and MAC)
						OFMatch matchServerToClient = new OFMatch();
						matchServerToClient.setDataLayerType(Ethernet.TYPE_IPv4);
						matchServerToClient.setNetworkProtocol(IPv4.PROTOCOL_TCP);
						matchServerToClient.setNetworkSource(hostIP);
						matchServerToClient.setNetworkDestination(ipPkt.getSourceAddress());
						matchServerToClient.setTransportSource(tcpPkt.getDestinationPort());
						matchServerToClient.setTransportDestination(tcpPkt.getSourcePort());
						
						ArrayList<OFAction> actionsS2C = new ArrayList<OFAction>();
						actionsS2C.add(new OFActionSetField(OFOXMFieldType.ETH_SRC, instance.getVirtualMAC()));
						actionsS2C.add(new OFActionSetField(OFOXMFieldType.IPV4_SRC, dstIP));
						
						ArrayList<OFInstruction> instructionsS2C = new ArrayList<OFInstruction>();
						instructionsS2C.add(new OFInstructionApplyActions(actionsS2C));
						instructionsS2C.add(new OFInstructionGotoTable(this.l3RoutingApp.getTable()));
						
						SwitchCommands.installRule(sw, this.table,
								(short)(SwitchCommands.DEFAULT_PRIORITY + 2),
								matchServerToClient, instructionsS2C,
								SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);
					}
					else
					{
						// Non-SYN TCP packet to virtual IP - send TCP reset
						// Construct TCP reset packet
						TCP tcpReset = new TCP();
						tcpReset.setSourcePort(tcpPkt.getDestinationPort());
						tcpReset.setDestinationPort(tcpPkt.getSourcePort());
						tcpReset.setSequence(tcpPkt.getAcknowledge());
						tcpReset.setAcknowledge(tcpPkt.getSequence() + 1);
						tcpReset.setDataOffset((byte)5);
						tcpReset.setFlags((short)0x14); // RST + ACK
						tcpReset.setWindowSize((short)0);
						
						// Construct IP packet
						IPv4 ipReset = new IPv4();
						ipReset.setSourceAddress(dstIP);
						ipReset.setDestinationAddress(ipPkt.getSourceAddress());
						ipReset.setProtocol(IPv4.PROTOCOL_TCP);
						ipReset.setTtl((byte)64);
						ipReset.setPayload(tcpReset);
						
						// Construct Ethernet frame
						Ethernet ethReset = new Ethernet();
						ethReset.setEtherType(Ethernet.TYPE_IPv4);
						ethReset.setSourceMACAddress(instance.getVirtualMAC());
						ethReset.setDestinationMACAddress(ethPkt.getSourceMACAddress());
						ethReset.setPayload(ipReset);
						
						// Send the reset
						SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), ethReset);
					}
					
					return Command.STOP;
				}
			}
		}
		
		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param switchId for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param switchId for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param switchId for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port, PortChangeType type) 
	{ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param switchId for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}