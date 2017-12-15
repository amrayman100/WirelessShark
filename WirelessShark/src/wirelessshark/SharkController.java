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
import javafx.fxml.Initializable;
import javafx.scene.control.TextArea;


public class SharkController implements Initializable {

  
public TextArea text;
  public Sniffing  s = new Sniffing();    
   
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        
        
        
        text = new TextArea();
    
    } 
     @FXML
        private void Start(ActionEvent event){

        s.start();
    }
     @FXML
       private void Stop(ActionEvent event){
          
           // s.pause();
           
            s.cancel();
             s.reset();
            System.out.println("Paused");
           
          
       
      }  
          @FXML
       private void s(ActionEvent event){
     
      }
         @FXML
        private void st(ActionEvent event){
      
       
      }  
        
       
}
