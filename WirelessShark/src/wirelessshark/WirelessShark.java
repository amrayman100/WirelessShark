/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wirelessshark;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import java.util.ArrayList;  
import java.util.Date;  
import java.util.List;  
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
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

/**
 *
 * @author Amr Ayman
 */
public class WirelessShark extends Application {
    
        public static Ip4 ip = new Ip4();
	public static Ethernet eth = new Ethernet();
	public static Tcp tcp = new Tcp();
	public static Udp udp = new Udp();
        public static Http http = new Http();
    
   
    static List<PcapIf> alldevs = new ArrayList<PcapIf>();
         boolean cancelled = false;
         
        
          static StringBuilder errbuf = new StringBuilder();
   
               
        
        static int r = Pcap.findAllDevs(alldevs, errbuf);   
         static PcapIf  device = alldevs.get(2);
    @Override
    public void start(Stage primaryStage) throws Exception{
        System.out.print("loay");
         int i = 0; 
         for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }  
  
         Parent root = FXMLLoader.load(getClass().getResource("Shark.fxml"));
        Scene scene = new Scene(root);
        
   
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        launch(args);
        
    }
    
}
