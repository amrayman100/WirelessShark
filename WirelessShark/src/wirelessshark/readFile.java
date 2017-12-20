/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wirelessshark;

import javafx.concurrent.Service;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.layout.Region;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import java.util.ArrayList;  
import java.util.Date;  
import java.util.List;  
  import org.jnetpcap.Pcap;

// chapter 2.6
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;

// to format data and get headers
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Rip;
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf;  
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;  
import static org.jnetpcap.protocol.JProtocol.TCP;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import javafx.concurrent.ScheduledService;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import java.net.URL;
import javafx.util.Duration;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.application.Platform;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.concurrent.Worker;
import javafx.concurrent.WorkerStateEvent;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.stage.Stage;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.concurrent.ScheduledService;
import javafx.concurrent.Task;
import javafx.concurrent.WorkerStateEvent;
import javafx.event.EventHandler;
import javafx.scene.control.TextArea;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.util.PcapPacketArrayList;
import static wirelessshark.Sniffing.arp;
import static wirelessshark.Sniffing.http;
import static wirelessshark.Sniffing.ip;

import java.nio.ByteBuffer;

public class readFile extends Service{
   private String FileAddress = "";
   public int count = 0;
    Pcap pcap;
    final StringBuilder errbuf = new StringBuilder();
     PcapPacketHandler<String> jpacketHandler;
   public readFile(String f){
       this.FileAddress = f;
       pcap = Pcap.openOffline(FileAddress, errbuf);
       System.out.print(errbuf);
       
       
        this.jpacketHandler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
           
             // System.out.print("in");
              //System.out.println(packet.toString());
               String c = Integer.toString(count);
               String Time = String.valueOf(packet.getCaptureHeader().timestampInMillis());
               
                 if(packet.hasHeader(http)){
                   
                     
                      
                   WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"HTTP",String.valueOf(packet.getCaptureHeader().wirelen()),http.fieldValue(Request.RequestUrl)));
                      //WirelessShark.packets.add(packet);  
                      count++;
                    
            
                 } 
                 else if(packet.hasHeader(arp)){
                       
                     WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"ARP",String.valueOf(packet.getCaptureHeader().wirelen()),""));
                      //WirelessShark.packets.add(packet);
                     count++;
                      
                 }
                 else if(packet.hasHeader(ip)){
                    
                      WirelessShark.content.add(new packetInfo(packet,c,Time, FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),ip.typeEnum().toString(),String.valueOf(packet.getCaptureHeader().wirelen()),""));
                      //WirelessShark.packets.add(packet);  
                      count++;
             
            
             
                 }
                
             
               
            }
        };
       
       
       
   }
   
   
     @Override
    protected Task createTask() {
        return new Task() {
            @Override
            protected Object call() throws Exception {
               
                    
                    //pcap.loop(1, jpacketHandler, "");
                    
                    pcap.loop(Pcap.LOOP_INFINITE,jpacketHandler,"s");
                
                
                       
                        
                return null;
            }
        };
  
        
}
   
   
}
