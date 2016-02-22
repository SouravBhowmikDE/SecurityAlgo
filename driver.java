/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package AES;

import java.util.Scanner;

/**
 * This class generates 11 round keys from an AES keys
 * @author Sourav
 */
public class driver {
    public static void main(String args[]){
        Scanner in = new Scanner(System.in);
         //Takes input from user and stores in inputkey
        String inputKey = in.nextLine();
        //If condition makes sure that user has entered exactly 32 hexadecimal digits
        if(inputKey.matches("[0-9A-F]{32}")){
            //Storing the W matrix from method aesRoundKeys in W
        Integer[][] W=aescipher.aesRoundKeys(inputKey);
          int ctr=1;
          //Printing the matrix elements that contain the 11 round keys one below the other
               for(int i=0;i<44;i++){
                   for(int j=0;j<4;j++){
                       if(ctr%16==0){
                       System.out.println(String.format("%02X", W[i][j]));
                       }
                       else{
                       System.out.print(String.format("%02X", W[i][j]));
                       
                       }
                       ctr++;
                   }
                   
               }
        }
        else{
            //If user input is incorrect, terminate the program
            System.out.println("Invalid input key, exiting.....");
            
        }
        
    }
    
}
