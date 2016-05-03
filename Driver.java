package AESALGORITHM_192;

/**
 * file: Driver.java author: SivaChintapalli & Sourav Bhowmik course:
 * MSCS_630L_231_16S assignment: Project due date: May 03, 2016 version: 1.0 his
 * file contains program of AES Algorithm which will generate the round keys
 *
 */
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

/**
 * This class reads the input from the file or takes input from user in
 * hexadecimal format and generate the ciphertext.
 *
 * @author SIVARAMAKRISHNAPRASAD & SOURAV BHOWMIK
 */
public class Driver {

    //roundKey stores all the generated roundKeys
    private static HashMap<Integer, String> roundKey = new HashMap<>();

    //decryptMsgList stores the decrypted message just before removing the padding
    private static List<String> decryptMsgList = new ArrayList<>();
    private static List<String> encryptMsgList = new ArrayList<>();

    public static void main(String[] args) {
        // takes the input from the user and stores in to the key
        System.out.println("Enter 0 for 128-bit encryption");
        System.out.println("Enter 1 for 192-bit encryption");
        System.out.println("Enter 2 for 256-bit encryption");
        Scanner input = new Scanner(System.in);

        //encryptionType stores the encryption mode(128, 192 or 256)
        String encryptionType = input.next();
        System.out.println("Enter 'e' for encryption");
        System.out.println("Enter 'd' for decryption");
        //mode stores the mode(determines whether to encrypt or decrypt)
        String mode = input.next();
        System.out.println("Enter the key");
        //key stores the key
        String key = input.next();
        String cipherText = "";
        AESCipher aesChiper = new AESCipher();
        //This snippet checks if the entered key length is same as the selected encryption bit length.  
        if (encryptionType.matches("[0-2]{1}")) {
            switch (encryptionType) {
                case "0":
                    if (key.matches("[0-9a-fA-F]{32}")) {
                        roundKey = aesChiper.aesRoundKey(key);
                    } else {
                        System.out.println("invalid key entered, try again");
                    }
                    break;
                case "1":
                    if (key.matches("[0-9a-fA-F]{48}")) {
                        roundKey = aesChiper.aesRoundKey(key);
                    } else {
                        System.out.println("invalid key entered, try again");
                    }
                    break;
                case "2":
                    if (key.matches("[0-9a-fA-F]{64}")) {
                        roundKey = aesChiper.aesRoundKey(key);
                    } else {
                        System.out.println("invalid key entered, try again");
                    }
                    break;
            }
            if (!roundKey.isEmpty()) {
                int rounds = roundKey.size();
                int encryptType;
                //this snippet determines the encryption type and sets the variable encryptType
                switch (rounds) {
                    case 11:
                        encryptType = 128;
                        break;
                    case 13:
                        encryptType = 192;
                        break;
                    default:
                        encryptType = 256;
                        break;
                }
                System.out.println("Enter the message");
                //message stores the message
                String message = input.next();
                if (message.length() % 2 == 0) {
                    String plainText;
                    int paddingSize;
                    //Dividing the message into blocks if size of message block is not equal to 128 bits. 
                    String[] arrayOfMessageBlocks = new String[message.length() / 4];
                    if (message.length() != 32) {
                        //Dividing the message into blocks if size of message block is greater than 128 bits. 
                        if (message.length() > 32) {
                            int x = 0;
                            String temp = "";
                            for (int j = 0; j < message.length(); j++) {
                                if (temp.length() < 32) {
                                    temp += message.charAt(j);
                                } else {
                                    arrayOfMessageBlocks[x] = temp;
                                    temp = "";
                                    temp += message.charAt(j);
                                    x++;
                                }
                            }
                            arrayOfMessageBlocks[x] = temp;
                        }
                        //Dividing the message into blocks if size of message block is smaller than to 128 bits. 
                        if (message.length() < 32) {
                            arrayOfMessageBlocks[0] = messagePadding(message);
                        }
                    } else {
                        arrayOfMessageBlocks[0] = message;
                    }
                    //Encrypting/decrypting the message blockwise
                    for (String eachBlock : arrayOfMessageBlocks) {
                        if (eachBlock != null) {
                            if (eachBlock.length() == 32) {
                                plainText = eachBlock;
                            } else {
                                plainText = messagePadding(eachBlock);
                            }
                            if (mode.equals("e")) {
                                String encryptMsg = aesChiper.encryption(plainText);
                                encryptMsgList.add(encryptMsg);
                            }
                            if (mode.equals("d")) {
                                String decryptMsg = aesChiper.decryption(plainText);
                                decryptMsgList.add(decryptMsg);
                            }
                        }
                    }
                } else {
                    System.out.println("Invalid PlainText entered, try again");
                }
                //Printing the encrypted message
                if (mode.equals("e")) {
                    System.out.println(encryptType + "-bit encrypted message is ");
                    for (String encryptMsgList1 : encryptMsgList) {
                        System.out.print(encryptMsgList1);
                    }
                }
                //Printing the decrypted message
                if (mode.equals("d")) {
                    System.out.println(encryptType + "-bit decrypted message is ");
                    removePadding();
                }
            }
        } else {
            System.out.println("invalid input entered, try again");
        }
    }

    /*
  This method pads the message to make it a block of 32 characters(16 hex numbers)
  @param message: the message to be padded
  @return the padded string
     */
    public static String messagePadding(String message) {
        StringBuffer str = new StringBuffer(message);
        //paddingSize stores the characters required to be padded
        int paddingSize = 32 - message.length();
        for (int i = 0; i < paddingSize / 2; i++) {
            if (paddingSize > 9) {
                str = str.append(paddingSize);
            } else {
                str = str.append("0").append(paddingSize / 2);
            }
        }
        return str.toString();
    }

    /*
    This method removes padding from the decrypted padded message 
     */
    public static void removePadding() {

        for (int k = 0; k < decryptMsgList.size(); k++) {
            if (decryptMsgList.size() > 1) {
                if (k == decryptMsgList.size() - 1) {
                    int count = 0;
                    String PaddedMsg = decryptMsgList.get(k);
                    String paddedVal = PaddedMsg.substring(30, 32);
                    for (int i = 0; i < 16; i++) {
                        String val = PaddedMsg.charAt(i * 2) + "" + PaddedMsg.charAt(i * 2 + 1);
                        if (paddedVal.equals(val)) {
                            count++;
                        }
                    }
                    if(count!=1){
                    if (count == Integer.parseInt(paddedVal)) {
                        PaddedMsg = PaddedMsg.replace(paddedVal, "");
                    }
                    System.out.print(PaddedMsg);
                }
                    else {
                    System.out.print(decryptMsgList.get(k));
                }
                }else {
                    System.out.print(decryptMsgList.get(k));
                }
            }else {
                    System.out.print(decryptMsgList.get(k));
                }
        }
    }

}
