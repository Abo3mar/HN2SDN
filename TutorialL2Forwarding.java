/*
 * Copyright (C) 2014 SDN Hub

 Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
 You may not use this file except in compliance with this License.
 You may obtain a copy of the License at

    http://www.gnu.org/licenses/gpl-3.0.txt

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 implied.

 *
 */

package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.lang.String;
import java.util.Map;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.packet.ARP;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.ICMP;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.Flood;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.sal.utils.NetUtils;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.switchmanager.Subnet;

public class TutorialL2Forwarding implements IListenDataPacket {
	
	private static final Logger logger = LoggerFactory
            .getLogger(TutorialL2Forwarding.class);
    // ISwitchManager contains all Information for all known nodes (i.e. switches) in the controller
    private ISwitchManager switchManager = null;
    // IFlowProgrammerService Interface for installing/modifying/removing flows on a network node
    private IFlowProgrammerService programmer = null;
    // IDataPacketService Data Packet Services SAL provides to the applications
    private IDataPacketService dataPacketService = null;
    // Hashtable contains Mac as key and Port as Value
    private Map<Long, NodeConnector> mac_to_port = new HashMap<Long, NodeConnector>();
    // Function contains the string that will decide whether we are using a switch or a hub
    private String function = "switch";

    void setDataPacketService(IDataPacketService s) {
        this.dataPacketService = s;
    }

    void unsetDataPacketService(IDataPacketService s) {
        if (this.dataPacketService == s) {
            this.dataPacketService = null;
        }
    }

    public void setFlowProgrammerService(IFlowProgrammerService s)
    {
        this.programmer = s;
    }

    public void unsetFlowProgrammerService(IFlowProgrammerService s) {
        if (this.programmer == s) {
            this.programmer = null;
        }
    }

    void setSwitchManager(ISwitchManager s) {
        logger.debug("SwitchManager set");
        this.switchManager = s;
    }

    void unsetSwitchManager(ISwitchManager s) {
        if (this.switchManager == s) {
            logger.debug("SwitchManager removed!");
            this.switchManager = null;
        }
    }

    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     *
     */
    void init() {
        logger.info("Initialized");
        // Disabling the SimpleForwarding and ARPHandler bundle to not conflict with this one
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        for(Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getSymbolicName().contains("simpleforwarding")) {
                try {
                    bundle.uninstall();
                } catch (BundleException e) {
                    logger.error("Exception in Bundle uninstall "+bundle.getSymbolicName(), e); 
                }   
            }   
        }   
 
    }

    /**
     * Function called by the dependency manager when at least one
     * dependency become unsatisfied or when the component is shutting
     * down because for example bundle is being stopped.
     *
     */
    void destroy() {
    }

    /**
     * Function called by dependency manager after "init ()" is called
     * and after the services provided by the class are registered in
     * the service registry
     *
     */
    void start() {
        logger.info("Started");
    }

    /**
     * Function called by the dependency manager before the services
     * exported by the component are unregistered, this will be
     * followed by a "destroy ()" calls
     *
     */
    void stop() {
        logger.info("Stopped");
    }

    private void floodPacket(RawPacket inPkt) {
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();

        Set<NodeConnector> nodeConnectors =
                this.switchManager.getUpNodeConnectors(incoming_node);

        for (NodeConnector p : nodeConnectors) {
            if (!p.equals(incoming_connector)) {
                try {
                    RawPacket destPkt = new RawPacket(inPkt);
                    destPkt.setOutgoingNodeConnector(p);
                    this.dataPacketService.transmitDataPacket(destPkt);
                } catch (ConstructionException e2) {
                    continue;
                }
            }
        }
    }
    
    // receiveDataPacket() calls --> floodPackets and ProgramFlow
    // Its main goal is to create the mac_to_port dictionary, it will
    // listen to all incoming packets
    @Override
    public PacketResult receiveDataPacket(RawPacket inPkt) {
    	
    	// A RawPacket will come in here
        if (inPkt == null) {
            return PacketResult.IGNORED;
        }
        // Extract Port Number - incoming_connector is the port from which the packet came in
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        
        // Hub implementation
        if (function.equals("hub")) {
            floodPacket(inPkt);		// Flood packets to all connected hosts
        } else {
            Packet formattedPak = this.dataPacketService.decodeDataPacket(inPkt);
            // If packet is not an instance of Ethernet packet then Ignore the packet
            if (!(formattedPak instanceof Ethernet)) {
                return PacketResult.IGNORED;
            }
            // Get source MAC by passing formattedPak and port - Store MAC and Port in the Dictionary mac_to_port
            learnSourceMAC(formattedPak, incoming_connector);
            // Get destination Port by passing formattedPak. Using the MAC in the formattedPak
            // the dictionary mac_to_port will be examined for any match and if a match exists
            // it will return port value.
            NodeConnector outgoing_connector = 
                knowDestinationMAC(formattedPak);
            // If outgoing_connector is null then you didn't find a match
            if (outgoing_connector == null) {
                floodPacket(inPkt);
            } else {
                if (!programFlow(formattedPak, incoming_connector,
                            outgoing_connector)) {
                    return PacketResult.IGNORED;
                }
                inPkt.setOutgoingNodeConnector(outgoing_connector);
                this.dataPacketService.transmitDataPacket(inPkt);
            }
        }
        return PacketResult.CONSUME;
    }

    // learnSourceMAC will put <MAC, PORT> in the Dictionary
    private void learnSourceMAC(Packet formattedPak, NodeConnector incoming_connector) {
        byte[] srcMAC = ((Ethernet)formattedPak).getSourceMACAddress();
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        this.mac_to_port.put(srcMAC_val, incoming_connector);
    }

    // knowDestinationMAC will search the dictionary mac_to_port for a match of a MAC address and 
    // if it finds a match it will return the port
    private NodeConnector knowDestinationMAC(Packet formattedPak) {
        byte[] dstMAC = ((Ethernet)formattedPak).getDestinationMACAddress();
        long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
        return this.mac_to_port.get(dstMAC_val) ;
    }

    private boolean programFlow(Packet formattedPak, 
            NodeConnector incoming_connector, 
            NodeConnector outgoing_connector) {
    	// Get dstMAC address
        byte[] dstMAC = ((Ethernet)formattedPak).getDestinationMACAddress();
        // Match is used to insert rules into the switch, Similar to POX's FLOW_MOD
        Match match = new Match();
        // set field IN_PORT = incoming_connector
        match.setField( new MatchField(MatchType.IN_PORT, incoming_connector) );
        // set filed DL_DST = dstMAC.clone() - clone() here copies the object dstMAC 
        // instead of passing a reference
        match.setField( new MatchField(MatchType.DL_DST, dstMAC.clone()) );
        // List of actions
        List<Action> actions = new ArrayList<Action>();
        // Adding an output action
        actions.add(new Output(outgoing_connector));
        // Now after creating the match and actions, create the flow
        Flow f = new Flow(match, actions);
        // Add IdleTimeout actions 
        f.setIdleTimeout((short)5);

        // Modify the flow on the network node (i.e, switch)
        Node incoming_node = incoming_connector.getNode();
        Status status = programmer.addFlow(incoming_node, f);

		/*
		 * Installed 
		 * flow Flow[match = Match [fields={IN_PORT=IN_PORT(OF|2@OF|00:00:00:00:00:00:00:01), DL_DST=DL_DST(00:00:00:00:00:02)}, matches=5],
		 * actions = [OUTPUT[OF|3@OF|00:00:00:00:00:00:00:01]], priority = 0, id = 0, idleTimeout = 5, hardTimeout = 0] 
		 * in node OF|00:00:00:00:00:00:00:01
		 * 
		 * Installed 
		 * flow Flow[match = Match [fields={IN_PORT=IN_PORT(OF|3@OF|00:00:00:00:00:00:00:01), DL_DST=DL_DST(00:00:00:00:00:01)}, matches=5], 
		 * actions = [OUTPUT[OF|2@OF|00:00:00:00:00:00:00:01]], priority = 0, id = 0, idleTimeout = 5, hardTimeout = 0] 
		 * in node OF|00:00:00:00:00:00:00:01
		 */
        if (!status.isSuccess()) {
            logger.warn("SDN Plugin failed to program the flow: {}. The failure is: {}",
                    f, status.getDescription());
            return false;
        } else {
        	logger.info("Installed flow {} in node {}/n",
                    f, incoming_node);
            return true;
        }
    }
}
