package wirelessshark;

import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;


public class SharkController implements Initializable {

  
public TextArea text;
  public Sniffing  s = new Sniffing();   
     @FXML
    private TableView<packetInfo> result;
  @FXML
    private JFXTextField filter = new JFXTextField();
  @FXML
  private JFXTextArea info = new JFXTextArea();
  
   @FXML
    private TableColumn<packetInfo, String> No,Time,Dest,Source,Length,Prot,Info;
  
   
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

        // 2. Set the filter Predicate whenever the filter changes.
        filter.textProperty().addListener((observable, oldValue, newValue) -> {
            filteredData.setPredicate(person -> {
                // If filter text is empty, display all packets.
                if (newValue == null || newValue.isEmpty()) {
                    return true;
                }

                // Compare first name and last name of every packets with filter text.
                String lowerCaseFilter = newValue.toLowerCase();

                if (person.getProtocol().getValue().toLowerCase().contains(lowerCaseFilter)) {
                    return true; // Filter matches first name.
                } 
                return false; // Does not match.
            });
        });
        
       result.setItems(filteredData);
        
        
    
    } 
     @FXML
        private void Start(ActionEvent event){

        s.start();
        
    }
        
       @FXML
        private void selected(){
           packetInfo selected = result.getSelectionModel().getSelectedItem();
           info.setText(selected.packet.toString());
      
          
         
        
    }  
        
     @FXML
       private void Stop(ActionEvent event){
          
     
            s.cancel();
             s.reset();
            System.out.println("Paused");
           
          
       
      }  
       @FXML
          public void fiterDisplay(){
     
}
          
  
        
       
}








