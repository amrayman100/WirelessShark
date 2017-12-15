package wirelessshark;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXTextField;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
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
    JFXButton dev0 = new JFXButton();
    @FXML 
    JFXButton dev1 = new JFXButton();
    @FXML 
    JFXButton dev2 = new JFXButton();
    @FXML 
    JFXButton dev3 = new JFXButton();
    @FXML 
    JFXButton dev4 = new JFXButton();
    @FXML
    JFXTextField title = new JFXTextField();
    
    
    //image = new Image("/Wireless/"+image);
    static List<PcapIf> alldevs = new ArrayList<PcapIf>();
         boolean cancelled = false;
         static StringBuilder errbuf = new StringBuilder();
         static int r = Pcap.findAllDevs(alldevs, errbuf);   
    
    

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        
         // cover.setImage("Shark.png");
        title.setEditable(false);
        if(alldevs.get(0).getDescription().equalsIgnoreCase("Microsoft")){
             dev0.setText(alldevs.get(0).getDescription()+" #0");
        }
        else{
              dev0.setText(alldevs.get(0).getDescription());
        }
        
         if(alldevs.get(1).getDescription().equalsIgnoreCase("Microsoft")){
             dev1.setText(alldevs.get(1).getDescription()+" #1");
        }
        else{
              dev1.setText(alldevs.get(1).getDescription());
        }
         
          if(alldevs.get(2).getDescription().equalsIgnoreCase("Microsoft")){
             dev2.setText(alldevs.get(2).getDescription()+" #2");
        }
        else{
              dev2.setText(alldevs.get(2).getDescription());
        }
          
           if(alldevs.get(3).getDescription().equalsIgnoreCase("Microsoft")){
             dev3.setText(alldevs.get(3).getDescription()+" #3");
        }
        else{
              dev3.setText(alldevs.get(3).getDescription());
        }
           
           
           if(alldevs.get(4).getDescription().equalsIgnoreCase("Microsoft")){
             dev4.setText(alldevs.get(4).getDescription()+" #4");
        }
        else{
              dev4.setText(alldevs.get(4).getDescription());
        }
          
     
       
    }    
    
     @FXML
    private void sniff0(ActionEvent event){
        WirelessShark.device = alldevs.get(0);
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
    
     @FXML
    
     private void sniff1(ActionEvent event){
        WirelessShark.device = alldevs.get(1);
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
     
      @FXML
      private void sniff2(ActionEvent event){
           WirelessShark.device = alldevs.get(2);
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
       @FXML
       private void sniff3(ActionEvent event){
            WirelessShark.device = alldevs.get(3);
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
        @FXML
        private void sniff4(ActionEvent event){
             WirelessShark.device = alldevs.get(4);
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


