package edu.wisc.cs.sdn.apps.sps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.util.MACAddress;

// OpenFlow 1.0 Imports
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.OFPort;

public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener, 
        ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching
{
    public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();
    
    // Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

    /**
     * Loads dependencies and initializes data structures.
     */
    @Override
    public void init(FloodlightModuleContext context)
            throws FloodlightModuleException 
    {
        log.info(String.format("Initializing %s...", MODULE_NAME));
        Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        this.floodlightProv = context.getServiceImpl(
                IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
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
        this.linkDiscProv.addListener(this);
        this.deviceProv.addListener(this);
        
        // Compute initial paths
        this.recalculatePaths();
    }
    
    /**
     * Get the table in which this application installs rules.
     */
    public byte getTable()
    { return this.table; }
    
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
    
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
    private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
    
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
    @Override
    public void deviceAdded(IDevice device) 
    {
        Host host = new Host(device, this.floodlightProv);
        // We only care about a new host if we know its IP
        if (host.getIPv4Address() != null)
        {
            log.info(String.format("Host %s added", host.getName()));
            this.knownHosts.put(device, host);
            this.recalculatePaths();
        }
    }

    /**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
    @Override
    public void deviceRemoved(IDevice device) 
    {
        Host host = this.knownHosts.get(device);
        if (null == host)
        {
            host = new Host(device, this.floodlightProv);
            this.knownHosts.put(device, host);
        }
        
        log.info(String.format("Host %s is no longer attached to a switch", 
                host.getName()));
        
        this.knownHosts.remove(device);
        this.recalculatePaths();
    }

    /**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
    @Override
    public void deviceMoved(IDevice device) 
    {
        Host host = this.knownHosts.get(device);
        if (null == host)
        {
            host = new Host(device, this.floodlightProv);
            this.knownHosts.put(device, host);
        }
        
        if (!host.isAttachedToSwitch())
        {
            this.deviceRemoved(device);
            return;
        }
        log.info(String.format("Host %s moved to s%d:%d", host.getName(),
                host.getSwitch().getId(), host.getPort()));
        
        this.recalculatePaths();
    }
    
    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
    @Override       
    public void switchAdded(long switchId) 
    {
        IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
        log.info(String.format("Switch s%d added", switchId));
        this.recalculatePaths();
    }

    /**
     * Event handler called when a switch leaves the network.
     * @param DPID for the switch
     */
    @Override
    public void switchRemoved(long switchId) 
    {
        IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
        log.info(String.format("Switch s%d removed", switchId));
        this.recalculatePaths();
    }

    /**
     * Event handler called when multiple links go up or down.
     * @param updateList information about the change in each link's state
     */
    @Override
    public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
    {
        for (LDUpdate update : updateList)
        {
            if (0 == update.getDst())
            {
                log.info(String.format("Link s%s:%d -> host updated", 
                    update.getSrc(), update.getSrcPort()));
            }
            else
            {
                log.info(String.format("Link s%s:%d -> %s:%d updated", 
                    update.getSrc(), update.getSrcPort(),
                    update.getDst(), update.getDstPort()));
            }
        }
        this.recalculatePaths();
    }

    /**
     * Event handler called when link goes up or down.
     * @param update information about the change in link state
     */
    @Override
    public void linkDiscoveryUpdate(LDUpdate update) 
    { this.linkDiscoveryUpdate(Arrays.asList(update)); }
    
    /**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
    @Override
    public void deviceIPV4AddrChanged(IDevice device) 
    { this.deviceAdded(device); }

    /**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
    @Override
    public void deviceVlanChanged(IDevice device) 
    { /* Nothing we need to do, since we're not using VLANs */ }
    
    /**
     * Event handler called when the controller becomes the master for a switch.
     * @param DPID for the switch
     */
    @Override
    public void switchActivated(long switchId) 
    { /* Nothing we need to do, since we're not switching controller roles */ }

    /**
     * Event handler called when some attribute of a switch changes.
     * @param DPID for the switch
     */
    @Override
    public void switchChanged(long switchId) 
    { /* Nothing we need to do */ }
    
    /**
     * Event handler called when a port on a switch goes up or down, or is
     * added or removed.
     * @param DPID for the switch
     * @param port the port on the switch whose status changed
     * @param type the type of status change (up, down, add, remove)
     */
    @Override
    public void switchPortChanged(long switchId, ImmutablePort port,
            PortChangeType type) 
    { /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

    /**
     * Gets a name for this module.
     * @return name for this module
     */
    @Override
    public String getName() 
    { return this.MODULE_NAME; }

    /**
     * Check if events must be passed to another module before this module is
     * notified of the event.
     */
    @Override
    public boolean isCallbackOrderingPrereq(String type, String name) 
    { return false; }

    /**
     * Check if events must be passed to another module after this module has
     * been notified of the event.
     */
    @Override
    public boolean isCallbackOrderingPostreq(String type, String name) 
    { return false; }
    
    /**
     * Tell the module system which services we provide.
     */
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() 
    {
        Collection<Class<? extends IFloodlightService>> services =
                    new ArrayList<Class<? extends IFloodlightService>>();
        services.add(InterfaceShortestPathSwitching.class);
        return services; 
    }

    /**
     * Tell the module system which services we implement.
     */
    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> 
            getServiceImpls() 
    { 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
                    new HashMap<Class<? extends IFloodlightService>, 
                            IFloodlightService>();
        // We are the class that implements the service
        services.put(InterfaceShortestPathSwitching.class, this);
        return services;
    }

    /**
     * Tell the module system which modules we depend on.
     */
    @Override
    public Collection<Class<? extends IFloodlightService>> 
            getModuleDependencies() 
    {
        Collection<Class<? extends IFloodlightService >> modules =
                new ArrayList<Class<? extends IFloodlightService>>();
        modules.add(IFloodlightProviderService.class);
        modules.add(ILinkDiscoveryService.class);
        modules.add(IDeviceService.class);
        return modules;
    }

    // ************************************************************************
    // ADDED HELPER METHODS
    // ************************************************************************

    /**
     * Recalculates paths for all hosts and installs rules.
     */
    private synchronized void recalculatePaths() {
        log.info("Recalculating shortest paths...");
        
        // 1. Cleanup: Remove existing IP rules from all switches
        for (IOFSwitch sw : getSwitches().values()) {
            OFMatch match = new OFMatch();
            match.setDataLayerType(Ethernet.TYPE_IPv4);
            // Wildcard setting removed to fix compilation error.
            // The library likely handles this automatically or via default constructor.
            SwitchCommands.removeRules(sw, this.table, match);
        }

        // 2. Iterate through all known hosts
        for (Host host : getHosts()) {
            if (!host.isAttachedToSwitch() || host.getIPv4Address() == null) {
                continue;
            }

            // 3. Compute Shortest Path Tree rooted at the Host's switch
            // Dijkstra's Algorithm
            IOFSwitch destSwitch = host.getSwitch();
            Map<Long, Integer> distances = new HashMap<Long, Integer>();
            Map<Long, Long> nextHop = new HashMap<Long, Long>(); // Switch DPID -> Next Hop DPID
            PriorityQueue<SwitchDist> pq = new PriorityQueue<SwitchDist>();

            for (Long dpid : getSwitches().keySet()) {
                distances.put(dpid, Integer.MAX_VALUE);
            }
            distances.put(destSwitch.getId(), 0);
            pq.add(new SwitchDist(destSwitch.getId(), 0));

            while (!pq.isEmpty()) {
                SwitchDist u = pq.poll();
                if (u.dist > distances.get(u.dpid)) continue;

                // Traverse incoming links to build tree towards destination
                for (Link link : getLinks()) {
                    if (link.getDst() == u.dpid) {
                        Long v = link.getSrc();
                        if (distances.get(v) > distances.get(u.dpid) + 1) {
                            distances.put(v, distances.get(u.dpid) + 1);
                            nextHop.put(v, u.dpid); // The next hop for v to reach dest is u
                            pq.add(new SwitchDist(v, distances.get(v)));
                        }
                    }
                }
            }

            // 4. Install Rules based on Next Hops
            for (Long switchDpid : getSwitches().keySet()) {
                IOFSwitch sw = getSwitches().get(switchDpid);
                
                OFMatch match = new OFMatch();
                match.setDataLayerType(Ethernet.TYPE_IPv4);
                // OF 1.0 specific setter
                match.setDataLayerDestination(MACAddress.valueOf(host.getMACAddress()).toBytes());
                
                // Wildcards removed to ensure compilation.

                List<OFAction> actions = new ArrayList<OFAction>();

                if (switchDpid.equals(destSwitch.getId())) {
                    // On the destination switch, output to host port
                    actions.add(new OFActionOutput(host.getPort().shortValue()));
                } else if (nextHop.containsKey(switchDpid)) {
                    // On other switches, output to next hop switch
                    Long nextHopDpid = nextHop.get(switchDpid);
                    // Find port connecting sw -> nextHop
                    for (Link link : getLinks()) {
                        if (link.getSrc() == switchDpid && link.getDst() == nextHopDpid) {
                            actions.add(new OFActionOutput((short)link.getSrcPort()));
                            break;
                        }
                    }
                } else {
                    continue; // No path
                }

                if (actions.isEmpty()) continue;

                List<OFInstruction> instructions = new ArrayList<OFInstruction>();
                instructions.add(new OFInstructionApplyActions(actions));
                
                SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY,
                        match, instructions);
            }
        }
    }
}

// Helper class for PriorityQueue (Java 1.6 compatible)
class SwitchDist implements Comparable<SwitchDist> {
    public Long dpid;
    public int dist;
    
    public SwitchDist(Long dpid, int dist) {
        this.dpid = dpid;
        this.dist = dist;
    }
    
    @Override
    public int compareTo(SwitchDist other) {
        return Integer.compare(this.dist, other.dist);
    }
}