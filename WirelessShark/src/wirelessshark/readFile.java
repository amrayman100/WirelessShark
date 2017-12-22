/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wirelessshark;



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
import static wirelessshark.Sniffing.arp;
import static wirelessshark.Sniffing.http;
import static wirelessshark.Sniffing.ip;
import static wirelessshark.Sniffing.tcp;
import static wirelessshark.Sniffing.udp;

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
           
           
               String c = Integer.toString(count);
               String Time = String.valueOf(packet.getCaptureHeader().timestampInMillis());
               
               if(packet.hasHeader(http)){
                   
                     String info = parsehttp(packet);
                     
                      
                   WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"HTTP",String.valueOf(packet.getCaptureHeader().wirelen()),info));
                    
                      count++;
                    
            
                 } 
                 else if(packet.hasHeader(arp)){
                       String info = "" + arp.hardwareTypeDescription();
                     WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"ARP",String.valueOf(packet.getCaptureHeader().wirelen()),info));
                 
                     count++;
                      
                 }
                 else if(packet.hasHeader(udp)){
                     String info = "Source: "+udp.source()+" Dest "+udp.destination();
                     if(udp.source()==53||udp.source()==53){
                          WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"DNS",String.valueOf(packet.getCaptureHeader().wirelen()),info));
                     }
                     
                 }
                 
                  else if(packet.hasHeader(udp)){
                      packet.hasHeader(ip);
                     if(udp.source()==443||udp.source()==443){
                         
                          WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"QUIC",String.valueOf(packet.getCaptureHeader().wirelen()),""));
                     }
                 }
                 else if(packet.hasHeader(ip)){
             
                     packet.hasHeader(tcp);
                     String info =  " Ack : " + tcp.flags_ACK() + " Syn : " + tcp.flags_SYN();
                      WirelessShark.content.add(new packetInfo(packet,c,Time, FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),ip.typeEnum().toString(),String.valueOf(packet.getCaptureHeader().wirelen()),info));
                      
                      count++;
             
                    
             
                 }
                
             
               
            }
        };
       
       
   }
   
   public void loadfile() {
         final StringBuilder errbuf = new StringBuilder(); 
        Pcap pcap = Pcap.openOffline(FileAddress, errbuf);
        
        if (pcap == null) {
            
        }
     
        PcapPacketHandler<PcapPacketArrayList> jpacketHandler = new PcapPacketHandler<PcapPacketArrayList>() {
            public void nextPacket(PcapPacket packet, PcapPacketArrayList PaketsList) {
              
                String c = Integer.toString(count);
               String Time = String.valueOf(packet.getCaptureHeader().timestampInMillis());
               
                    if(packet.hasHeader(http)){
                   
                     String info = parsehttp(packet);
                     
                      
                   WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"HTTP",String.valueOf(packet.getCaptureHeader().wirelen()),info));
                      
                      count++;
                    
            
                 } 
                 else if(packet.hasHeader(arp)){
                       String info = "";
                     WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"ARP",String.valueOf(packet.getCaptureHeader().wirelen()),info));
                      
                     count++;
                      
                 }
                 else if(packet.hasHeader(udp)){
                     String info = "Source: "+udp.source()+" Dest "+udp.destination();
                     if(udp.source()==53||udp.source()==53){
                          WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"DNS",String.valueOf(packet.getCaptureHeader().wirelen()),info));
                     }
                      if(udp.source()==443||udp.source()==443){
                         
                          WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"QUIC",String.valueOf(packet.getCaptureHeader().wirelen()),info));
                     }
                 }
                 
               
                 else if(packet.hasHeader(ip)){
             
                     packet.hasHeader(tcp);
                     String info =  " Ack : " + tcp.flags_ACK() + " Syn : " + tcp.flags_SYN();
                      WirelessShark.content.add(new packetInfo(packet,c,Time, FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),ip.typeEnum().toString(),String.valueOf(packet.getCaptureHeader().wirelen()),info));
                       
                      count++;
             
                    
             
                 }
                
             
               
            }
        };
        try {
            PcapPacketArrayList packets = new PcapPacketArrayList();
            pcap.loop(-1,jpacketHandler,packets);
        } finally {
          
            pcap.close();
}
   }
   
   
   
      public String parsehttp(PcapPacket packet){
         String info = "";
           
                final String code = http.fieldValue(Http.Response.ResponseCode);  
                final String ct = http.fieldValue(Http.Response.Content_Type);  
                String cl = http.fieldValue(Http.Response.Content_Length);  
                final int payload = http.getPayloadLength();  
         
         packet.hasHeader(http);
         
          if (http.getMessageType() == Http.MessageType.RESPONSE) {  
                     info = http.fieldValue(Http.Response.ResponseCodeMsg)+" "+http.fieldValue(Http.Response.ResponseCode);
                }  
          
          if(http.getMessageType() == Http.MessageType.REQUEST){
              info =  http.fieldValue(Request.RequestMethod)+" /"+http.fieldValue(Request.RequestUrl);
          }
  
         
         
         return info;
     }
   
   
   
     @Override
    protected Task createTask() {
        return new Task() {
            @Override
            protected Object call() throws Exception {
               
                    
                
                    
                    pcap.loop(Pcap.LOOP_INFINITE,jpacketHandler,"s");
                
                
                       
                        
                return null;
            }
        };
  
        
}
   
   
}
