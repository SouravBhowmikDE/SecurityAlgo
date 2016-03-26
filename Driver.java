package AES;
import java.util.Scanner;
/**
 * This class generates 11 round keys from an AES key and prints the generated ciphertext
 *
 * @author Sourav
 */
public class Driver {
  public static void main(String args[]) {
    //Takes input from user and stores in inputkey
    Scanner in1 = new Scanner(System.in);
    String inputKey = in1.nextLine();
    
    //Takes 2nd input from user and stores in inputPlainText
    Scanner in2 = new Scanner(System.in);
    String inputPlainText = in2.nextLine();
    //If condition makes sure that user has entered exactly 32 hexadecimal digits
    if ( (inputKey.matches("[0-9A-F]{32}") ) && (inputPlainText.matches("[0-9A-F]{32}"))) {
      
      //C stores the ciphertext
      Integer[][] C = Aescipher.aes(inputPlainText, inputKey);
      
      //Printing the ciphertext C
      for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
          System.out.print(String.format("%02X", C[i][j]));
        }
      }
    } else {
      //If user input is incorrect, terminate the program
      System.out.println("Invalid input key or plaintext, exiting.....");
    }
  }
}
