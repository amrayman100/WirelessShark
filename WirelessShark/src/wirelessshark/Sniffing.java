/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wirelessshark;


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
import java.text.SimpleDateFormat;
import java.util.Calendar;
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
import org.jnetpcap.PcapDumper;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Http.Response;


/**
 * FXML Controller class
 *
 * @author Amr Ayman
 * 
 */
 public class Sniffing extends Service {
  
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();
        int snaplen;
        int flags;  
        int timeout;           
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        public int count = 0;
          String ofile;
           public static final String DATE_FORMAT_NOW = "yyyyMMddHHmmss";
   
         String fname = "test-afs.pcap";  
  

         PcapIf  device = alldevs.get(0);
         Pcap pcap;
         public static Ip4 ip = new Ip4();
	public static Ethernet eth = new Ethernet();
	public static Tcp tcp = new Tcp();
	public static Udp udp = new Udp();
	public static Arp arp = new Arp();
          public static Http http = new Http(); 

          PcapPacketHandler<String> jpacketHandler;
       public Sniffing(){
          ofile = "SavedPackets\\SavedPackets"+Integer.toString(count)+ now() + ".pcap";
           this.errbuf = new StringBuilder(); 
        this.snaplen = 64 * 1024;           
        this.flags = Pcap.MODE_PROMISCUOUS;
        this.timeout = 10 * 1000;          
        this.pcap = Pcap.openLive(WirelessShark.device.getName(), this.snaplen, this.flags, this.timeout, this.errbuf);
         if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + this.errbuf.toString());
            return;
            
            
}
          PcapDumper dumper;  

 dumper = pcap.dumpOpen(ofile);
         
        
        this.jpacketHandler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
              dumper.dump(packet.getCaptureHeader(),packet);
             
               String c = Integer.toString(count);
              
                Date t = new Date(packet.getCaptureHeader().timestampInMillis());
                  String Time = String.valueOf(t);
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
                          count++;
                     }
                     
                     if(udp.source()==443||udp.source()==443){
                         
                          WirelessShark.content.add(new packetInfo(packet,c,Time,FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination()),"QUIC",String.valueOf(packet.getCaptureHeader().wirelen()),info));
                          count++;
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


       @Override
    protected Task createTask() {
        return new Task() {
            @Override
            protected Object call() throws Exception {
                while (true){
                    if(isCancelled()) {
                        break;
                    }
                    
                    pcap.loop(1, jpacketHandler, "");
                }
                //count = 0;
                return null;
            }
        };
}
    
     public static String now() {
		Calendar cal = Calendar.getInstance();
		SimpleDateFormat df = new SimpleDateFormat(DATE_FORMAT_NOW);
		return df.format(cal.getTime());
	}
     
     public String parsehttp(PcapPacket packet){
         String info = "";
           
              
         
         packet.hasHeader(http);
         
          if (http.getMessageType() == Http.MessageType.RESPONSE) {  
                     info = http.fieldValue(Response.ResponseCodeMsg)+" "+http.fieldValue(Response.ResponseCode);
                }  
          
          if(http.getMessageType() == Http.MessageType.REQUEST){
              info =  http.fieldValue(Request.RequestMethod)+" /"+http.fieldValue(Request.RequestUrl);
          }
  
         
         
         return info;
     }

 }
