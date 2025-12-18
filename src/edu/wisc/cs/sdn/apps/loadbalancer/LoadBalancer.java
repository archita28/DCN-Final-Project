package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.l3routing.IL3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType; // Fixed Import
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort; // Fixed Import
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener, IOFMessageListener {
    public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    private IFloodlightProviderService floodlightProv;
    private IDeviceService deviceProv;
    private IL3Routing l3RoutingApp;
    private byte table;
    private Map<Integer,LoadBalancerInstance> instances;

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info(String.format("Initializing %s...", MODULE_NAME));
        Map<String,String> config = context.getConfigParams(this);
        try {
            this.table = Byte.parseByte(config.get("table"));
            this.instances = new HashMap<Integer,LoadBalancerInstance>();
            String[] instanceConfigs = config.get("instances").split(";");
            for (String instanceConfig : instanceConfigs) {
                String[] configItems = instanceConfig.trim().split("\\s+");
                if (configItems.length != 3) { continue; }
                LoadBalancerInstance instance = new LoadBalancerInstance(
                        configItems[0], configItems[1], configItems[2].split(","));
                this.instances.put(instance.getVirtualIP(), instance);
                log.info("Added LB Instance: " + configItems[0]);
            }
        } catch (Exception e) { log.error("Config Error", e); }
        
        this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(IL3Routing.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info(String.format("Starting %s...", MODULE_NAME));
        this.floodlightProv.addOFSwitchListener(this);
        this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
    }
    
    @Override
    public void switchAdded(long switchId) {
        IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
        for (LoadBalancerInstance instance : instances.values()) {
            OFMatch matchTCP = new OFMatch();
            matchTCP.fromString("dl_type=0x0800,nw_proto=6,nw_dst=" + IPv4.fromIPv4Address(instance.getVirtualIP()));
            SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, matchTCP, 
                Arrays.asList((OFInstruction)new OFInstructionApplyActions(Arrays.asList((OFAction)new OFActionOutput(OFPort.OFPP_CONTROLLER)))));
            
            OFMatch matchARP = new OFMatch();
            matchARP.fromString("dl_type=0x0806,nw_dst=" + IPv4.fromIPv4Address(instance.getVirtualIP()));
            SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, matchARP, 
                Arrays.asList((OFInstruction)new OFInstructionApplyActions(Arrays.asList((OFAction)new OFActionOutput(OFPort.OFPP_CONTROLLER)))));
        }
    }
    
    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (msg.getType() != OFType.PACKET_IN) { return Command.CONTINUE; }
        OFPacketIn pktIn = (OFPacketIn)msg;
        Ethernet ethPkt = new Ethernet();
        ethPkt.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);
        
        // Handle ARP
        if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
            ARP arpPkt = (ARP) ethPkt.getPayload();
            int targetIP = IPv4.toIPv4Address(arpPkt.getTargetProtocolAddress());
            if (instances.containsKey(targetIP)) {
                LoadBalancerInstance instance = instances.get(targetIP);
                ARP arpReply = new ARP().setHardwareType(ARP.HW_TYPE_ETHERNET).setProtocolType(ARP.PROTO_TYPE_IP)
                        .setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH).setProtocolAddressLength((byte) 4)
                        .setOpCode(ARP.OP_REPLY).setSenderHardwareAddress(instance.getVirtualMAC()).setSenderProtocolAddress(instance.getVirtualIP())
                        .setTargetHardwareAddress(arpPkt.getSenderHardwareAddress()).setTargetProtocolAddress(arpPkt.getSenderProtocolAddress());
                
                // FIX: Break chain to avoid compilation error
                Ethernet ethReply = new Ethernet();
                ethReply.setSourceMACAddress(instance.getVirtualMAC());
                ethReply.setDestinationMACAddress(ethPkt.getSourceMACAddress());
                ethReply.setEtherType(Ethernet.TYPE_ARP);
                ethReply.setPayload(arpReply);
                
                SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), ethReply);
                return Command.STOP;
            }
        } 
        // Handle TCP (Manual Forwarding)
        else if (ethPkt.getEtherType() == Ethernet.TYPE_IPv4) {
            IPv4 ipPkt = (IPv4) ethPkt.getPayload();
            if (ipPkt.getProtocol() == IPv4.PROTOCOL_TCP) {
                if (instances.containsKey(ipPkt.getDestinationAddress())) {
                    LoadBalancerInstance instance = instances.get(ipPkt.getDestinationAddress());
                    int hostIP = instance.getNextHostIP();
                    byte[] hostMAC = getHostMACAddress(hostIP);
                    short outPort = getAttachmentPort(hostIP, sw.getId());
                    
                    if (hostMAC != null && outPort != 0) {
                        ethPkt.setDestinationMACAddress(hostMAC);
                        ipPkt.setDestinationAddress(hostIP);
                        ipPkt.setChecksum((short)0);
                        SwitchCommands.sendPacket(sw, outPort, ethPkt);
                        return Command.STOP;
                    }
                }
            }
        }
        return Command.CONTINUE;
    }

    private byte[] getHostMACAddress(int hostIPAddress) {
        Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(null, null, hostIPAddress, null, null);
        if (!iterator.hasNext()) { return null; }
        IDevice device = iterator.next();
        return MACAddress.valueOf(device.getMACAddress()).toBytes();
    }
    
    private short getAttachmentPort(int ip, long switchDPID) {
        Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(null, null, ip, null, null);
        if (iterator.hasNext()) {
            IDevice device = iterator.next();
            for (SwitchPort sp : device.getAttachmentPoints()) {
                if (sp.getSwitchDPID() == switchDPID) return (short)sp.getPort();
            }
        }
        return 0;
    }

    @Override public void switchRemoved(long switchId) { }
    @Override public void switchActivated(long switchId) { }
    @Override public void switchPortChanged(long switchId, ImmutablePort port, PortChangeType type) { }
    @Override public void switchChanged(long switchId) { }
    @Override public Collection<Class<? extends IFloodlightService>> getModuleServices() { return null; }
    @Override public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() { return null; }
    @Override public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService >> modules = new ArrayList<Class<? extends IFloodlightService>>();
        modules.add(IFloodlightProviderService.class);
        modules.add(IDeviceService.class);
        return modules;
    }
    @Override public String getName() { return MODULE_NAME; }
    @Override public boolean isCallbackOrderingPrereq(OFType type, String name) { return false; }
    @Override public boolean isCallbackOrderingPostreq(OFType type, String name) { 
        return (type == OFType.PACKET_IN && name.equals(ArpServer.MODULE_NAME)); 
    }
}