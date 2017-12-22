
package wirelessshark;


import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXSnackbar;
import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import java.awt.Insets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.jnetpcap.packet.PcapPacket;


public class SharkController implements Initializable {
 @FXML
public JFXButton Start = new JFXButton();
  @FXML
public JFXButton Stop = new JFXButton();
   @FXML
public JFXButton open = new JFXButton();
public TextArea text;
 public Sniffing  s = new Sniffing();
 @FXML
 private AnchorPane pane = new AnchorPane();
 
  
     @FXML
    private TableView<packetInfo> result;
  @FXML
    private JFXTextField filter = new JFXTextField();
  @FXML
  private JFXTextArea info = new JFXTextArea();
  
   @FXML
    private TableColumn<packetInfo, String> No,Time,Dest,Source,Length,Prot,Info;
       final FileChooser fileChooser = new FileChooser();
       readFile r;
   
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        
        No.setCellValueFactory(cellData -> cellData.getValue().getNumber());
       Time.setCellValueFactory(cellData -> cellData.getValue().getTime());
      Dest.setCellValueFactory(cellData -> cellData.getValue().getDest());
     Source.setCellValueFactory(cellData -> cellData.getValue().getSource());
          Length.setCellValueFactory(cellData -> cellData.getValue().getLength());
               Prot.setCellValueFactory(cellData -> cellData.getValue().getProtocol());
     Info.setCellValueFactory(cellData -> cellData.getValue().getInfo());


        
        text = new TextArea();
        
        FilteredList<packetInfo> filteredData = new FilteredList<>(WirelessShark.content, p -> true);

        filter.textProperty().addListener((observable, oldValue, newValue) -> {
            filteredData.setPredicate(person -> {
                
                if (newValue == null || newValue.isEmpty()) {
                    return true;
                }

               
                String lowerCaseFilter = newValue.toLowerCase();

                if (person.getProtocol().getValue().toLowerCase().contains(lowerCaseFilter)) {
                    return true; 
                } 
                return false;
            });
        });
        
       result.setItems(filteredData);
        
      
    
    } 
     @FXML
        private void Start(ActionEvent event){
             JFXSnackbar snack = new JFXSnackbar(pane);
             snack.show("Packet Capturing Started",3000);
        WirelessShark.content.clear();
        s.start();
       
        Start.setDisable(true);
        open.setDisable(true);
        s.count = 0;
       
        
       
         
    }
        
       @FXML
        private void selected(){
           packetInfo selected = result.getSelectionModel().getSelectedItem();
           if(selected == null){
               return;
           }
           info.setText(selected.packet.toString());
      
          
         
        
    }  
        
     @FXML
       private void Stop(ActionEvent event){
          
     
             s.cancel();
             s.reset();
          
            System.out.println("Paused");
           Start.setDisable(false);
           open.setDisable(false);
            JFXSnackbar snack = new JFXSnackbar(pane);
            snack.show("Packet Capturing Stopped",3000);
       
      }  
     
       
           @FXML
       private void open(ActionEvent event){
           
           
            
     
             WirelessShark.content.clear();
           
          Stage primaryStage = new Stage();
      
                  File file = fileChooser.showOpenDialog(primaryStage);
                  //FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter( "CAP","*.cap");
                  //FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter( "CAP","*.cap");
                  //fileChooser.getExtensionFilters().add(extFilter);
                if(file == null){
                  
                }else{
                    r = new readFile(file.getAbsoluteFile().getAbsolutePath());
                    System.out.println(file.getAbsoluteFile());
               
                       r.loadfile();
                
                }
                
                 JFXSnackbar snack = new JFXSnackbar(pane);
             snack.show("Packets Loading",3000);
            Start.setDisable(false);
    
       
       }
          @FXML
       private void back(ActionEvent event) throws Exception{
           if(s.isRunning()){
               s.cancel();
             s.reset();
           }
            WirelessShark.content.clear();
              Parent root = FXMLLoader.load(getClass().getResource("MainMenu.fxml"));
        Scene scene = new Scene(root);
         Stage stage=(Stage)((Node)event.getSource()).getScene().getWindow();
   
       stage.setScene(scene);
       
       stage.show();
       }
       
       
}
