/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wirelessshark;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import org.jnetpcap.packet.PcapPacket;


public class packetInfo {
    public PcapPacket packet;
    private final StringProperty no;
    private final StringProperty time;
    private final StringProperty source;
    private final StringProperty dest;
    private final StringProperty prot;
    private final StringProperty len;
    private final StringProperty info;
    
        public packetInfo() {
        this(null,null, null,null,null,null,null,null);
    }
    public packetInfo(PcapPacket p,String no, String time, String source, String dest,String prot,String len,String info) {
        this.packet = p;
        this.no =  new SimpleStringProperty(no);
        this.time =  new SimpleStringProperty(time);
        this.source=  new SimpleStringProperty(source);
        this.dest = new SimpleStringProperty(dest);
        this.prot = new SimpleStringProperty(prot);
        this.len = new SimpleStringProperty(len);
        this.info = new SimpleStringProperty(info);
    }
    
     public StringProperty getNumber() {
        return no;
    }

    public StringProperty getTime() {
         return time;
    }
    
      public StringProperty getSource() {
         return source;
    }
        public StringProperty getDest() {
         return dest;
    }
         public StringProperty getProtocol() {
         return prot;
    }
          public StringProperty getLength() {
         return len;
    }
           public StringProperty getInfo() {
         return info;
    }
       public void setNumber(String no) {
        this.no.set(no);
    }
       public void setTime(String time) {
        this.time.set(time);
    }
        public void setSource(String source) {
        this.source.set(source);
    }
      public void setDest(String dest) {
        this.dest.set(dest);
    }
      public void setProtocol(String prot) {
        this.prot.set(prot);
    }
      public void setLength(String len) {
        this.len.set(len);
    }
      public void setInfo(String info) {
        this.info.set(info);
    }
      
    
}



