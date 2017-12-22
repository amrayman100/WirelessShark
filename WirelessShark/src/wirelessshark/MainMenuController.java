package wirelessshark;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXTextField;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.Region;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import static wirelessshark.WirelessShark.alldevs;


public class MainMenuController implements Initializable {

    @FXML
    ImageView cover;
    @FXML 
    ComboBox list = new ComboBox();
    
    @FXML
    JFXButton start = new JFXButton();
    
    
 
    static List<PcapIf> alldevs = new ArrayList<PcapIf>();
         boolean cancelled = false;
         static StringBuilder errbuf = new StringBuilder();
         static int r = Pcap.findAllDevs(alldevs, errbuf);  
         ObservableList<String> options = FXCollections.observableArrayList();
        
   

    @Override
    public void initialize(URL url, ResourceBundle rb) {
         for (PcapIf device : alldevs) {  
            options.add(device.getDescription());
        }  
         // cover.setImage("Shark.png");
     
        list.setItems(options);
    
        
     
       
    }    
    
   
    
     @FXML
    
     private void start(ActionEvent event){
        
         int a = list.getSelectionModel().getSelectedIndex();
        WirelessShark.device = alldevs.get(a);
              FXMLLoader loader = new FXMLLoader();
           loader.setLocation(getClass().getResource("Shark.fxml"));
         try {
             loader.load();       
        } catch(Exception e) {
           e.printStackTrace();
          }
        Stage stage=(Stage)((Node)event.getSource()).getScene().getWindow();
        Parent root1 = loader.getRoot();            
        Scene scene1 = new Scene(root1);
        stage.setScene(scene1);
        stage.show();
        stage.setResizable(false);
        
      }
     
     
    
    
    
}