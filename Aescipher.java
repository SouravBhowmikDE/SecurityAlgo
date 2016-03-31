package AES;

import java.util.HashMap;
import java.util.Map;
/* This class generates 11 round keys and a ciphertext from a given plaintext 
   and an AES Encryption key
 *
 * @author Sourav
 */

public class Aescipher {

  //Sbox stores the look up table S-Box 
  static Map<Integer, Integer> Sbox = new HashMap();

  //3D matrix that stores the 11 round keys in eleven 4*4 planes(2D arrays)
  protected static Integer[][][] Keys = new Integer[11][4][4];

  //The fixed matrix used for column mixing
  static Integer[][] GaloisMatrix = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
  };
  //Stores substitution box arrays
  static Integer[] SboxArray = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
  };

  //Rcon stores the round constant look up table
  static Integer[] Rcon = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
  };

  /* This function returns a hex integer from a look up table stored in a 
     hashmap
   * @param inHex input hex Integer to be transformed
   * @return the transformed value from look up table
   */
  protected static Integer aesSbox(Integer inHex) {
    return Sbox.get(inHex);
  }
  /*This function returns a round constant
   * @param round is the "round number" of AES that ranges from 0 to 10 in this
     implementation
   * @return the round constant value from the look up table
   */

  protected static Integer aesRcon(Integer round) {
    return Rcon[round];
  }

  /**
   * This function generates 11 round keys from one Encryption key
   *
   * @param KeyHex is the encryption key
   * @return returns a matrix which contains 11 round keys
   */
  protected static Integer[][] aesRoundKeys(String KeyHex) {
    //Ke stores the encryption key
    Integer[][] Ke = StringToIntMatrix(KeyHex);

    //W stores 11 round keys
    Integer[][] W = new Integer[44][4];
    //putting the Sbox values from array to Hashmap for faster access
    for (int i = 0x00; i <= 0xff; i++) {
      Sbox.put(i, SboxArray[i]);
    }

    //Filling up first 4 rows of W
    System.arraycopy(Ke, 0, W, 0, 4);
    //Operation on next 40 rows
    for (int currentRow = 4; currentRow < 44; currentRow++) {
      //Calculating Round number and storing in RoundNo
      int RoundNo = currentRow / 4;
      if (currentRow % 4 != 0) {
        W[currentRow] = xor(W[currentRow - 4], W[currentRow - 1]);
      } else {
        //Wnew is a temporary vector
        Integer[] Wnew = new Integer[4];
        //Left Shifting Wnew by 1
        for (int i = 0; i < 4; i++) {
          Wnew[i] = W[currentRow - 1][(i + 1) % 4];
        }
        //Transforming Wnew using Sbox
        for (int i = 0; i < 4; i++) {
          Wnew[i] = aesSbox(Wnew[i]);
        }
        //Xoring round constant with Wnew[0]
        Wnew[0] = Wnew[0] ^ aesRcon(RoundNo);
        W[currentRow] = xor(W[currentRow - 4], Wnew);
      }
    }
    return W;
  }
  /*
   This function converts a String to a 4*4 Integer matrix
   @param AnyString is the input String to be converted
   @return the 4*4 matrix
   */

  protected static Integer[][] StringToIntMatrix(String AnyString) {
    Integer[][] Converted = new Integer[4][4];
    StringBuilder ThatString = new StringBuilder();
    ThatString.append(AnyString);
    for (int i = 2; i < ThatString.length(); i = i + 3) {
      ThatString.insert(i, ',');
    }
    //EncryptionKeyArr is an array of hexStrings
    String[] EncryptionKeyArr = ThatString.toString().split(",");
    //Copying values from  EncryptionKeyArr array into Ke[4][4] matrix
    int k = 0;
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        Converted[i][j] = Integer.parseInt(EncryptionKeyArr[k++], 16);
      }
    }
    return Converted;
  }
  /*
   * This function bitwise xors elements of two 1D matrices with 4 elements each
   * @param Vector1 is the first matrix
   * @param Vector2 is the second vector
   * @return ResultantVector is the xor result
   */

  protected static Integer[] xor(Integer Vector1[], Integer Vector2[]) {
    Integer[] ResultantVector = new Integer[4];
    for (int i = 0; i < 4; i++) {
      ResultantVector[i] = Vector1[i] ^ Vector2[i];
    }
    return ResultantVector;
  }

  /* This function xors two 4*4 matrices and outputs the result
   * @param sHex is the first input matrix
   * @param keyHex is the second input matrix
   * @return outStateHex is the xored result
   */
  protected static Integer[][] aesStateXOR(Integer[][] sHex,Integer[][] keyHex){
    Integer[][] outStateHex = new Integer[4][4];
    for (int i = 0; i < 4; i++) {
      outStateHex[i] = xor(sHex[i], keyHex[i]);
    }
    return outStateHex;
  }

  /* This function substitutes each element of a 4*4 matrix using the AES S-box 
   * @param inStateHex is the input matrix
   * @return outStateHex is the substituted matrix
   */
  protected static Integer[][] aesNibbleSub(Integer[][] inStateHex) {
    Integer[][] outStateHex = new Integer[4][4];
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        outStateHex[i][j] = aesSbox(inStateHex[i][j]);
      }
    }
    return outStateHex;
  }

  /* This function left shifts each element by their row number 
   * @param inStateHex is the 4*4 input matrix
   * @return outStateHex is the 4*4 shifted matrix
   */
  protected static Integer[][] aesShiftRow(Integer[][] inStateHex) {
    Integer[][] outStateHex = new Integer[4][4];
    int counter = 0;
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        outStateHex[i][j] = inStateHex[i][(j + counter) % 4];
      }
      counter++;
    }
    return outStateHex;
  }

  /*
   This method multiplies a hex number by 2 and returns the result
   @param a is the input to be multiplied by 2
   @return the product
   */
  protected static Integer multiply2(Integer InputHex) {
    StringBuilder ABinary = new StringBuilder();
    String ABinString;
    ABinString = Integer.toBinaryString(InputHex);

    //NumZero stores the no. of zeroes to pad with
    int NumZero = 8 - ABinString.length();
    ABinary.append(ABinString);

    //Padding with zeroes now
    for (int i = 0; i < NumZero; i++) {
      ABinary.insert(0, '0');
    }
    Integer padded;
    padded = Integer.parseInt((ABinary.substring(1) + "0"), 2);
    //shiftedNum stores the number after it has been left shifted by 1 
    String shiftedNum = Integer.toHexString(padded);
    Integer Snum = Integer.parseInt(shiftedNum, 16);

    //If the MSB of InputHex is 1, xor it with 1B
    if (NumZero == 0) {
      return ((Snum) ^ (0x1b));
    } else {
      return Snum;
    }

  }

  /*
   This method multiplies a hex number by 3 and returns the result
   @param InputHex is the input to be multiplied by 3
   @return the product
   */
  protected static Integer multiply3(Integer InputHex) {
    return (multiply2(InputHex) ^ InputHex);
  }

  /*
   This method uses GaloisMatrix to mix/multiply the columns of the 4*4 
   input matrix
   @param inStateHex the input matrix
   @return mixed/multiplied Matrix which is 4*4
   */
  protected static Integer[][] aesMixColumn(Integer[][] inStateHex) {
    Integer sum;
    Integer Product[][] = new Integer[4][4];
    for (int c = 0; c < 4; c++) {
      for (int d = 0; d < 4; d++) {
        sum = 0;
        for (int k = 0; k < 4; k++) {
          switch (GaloisMatrix[c][k]) {
            case 0x01:
              sum = sum ^ inStateHex[k][d];
              break;
            case 0x02:
              sum = sum ^ multiply2(inStateHex[k][d]);
              break;
            case 0x03:
              sum = sum ^ multiply3(inStateHex[k][d]);
              break;
          }
        }
        Product[c][d] = sum;
      }
    }
    return Product;
  }

  /*
   This method returns the transpose of th input matrix
   @param InputMatrix is the 4*4 matrix to be transposed
   @return transposed 4*4 matrix
   */
  protected static Integer[][] transpose(Integer[][] InputMatrix) {
    Integer OutputMatrix[][] = new Integer[4][4];
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        OutputMatrix[i][j] = InputMatrix[j][i];
      }
    }
    return OutputMatrix;
  }

  /*
   This methods performs one full round of AES encryption
   @param input is the intermediate AES result
   @param RoundNum is the round number
   @return the next intermediate AES result
   */
  protected static Integer[][] oneRound(Integer[][] input, int RoundNum) {
    Integer[][] SboxResult, ShiftResult, XORresult;
    SboxResult = aesNibbleSub(input);
    ShiftResult = aesShiftRow(SboxResult);
    if (RoundNum != 10) {
      Integer[][] MixColumnResult = aesMixColumn(ShiftResult);
      XORresult = aesStateXOR(MixColumnResult, transpose(Keys[RoundNum]));
    } else {
      //No need for columnMix in the 10th round
      XORresult = aesStateXOR(ShiftResult, transpose(Keys[RoundNum]));
    }
    return XORresult;
  }

  /*
   This function encrypts the plaintexr with the key to produce a ciphertext
   @param pTextHex is the plaintext
   @param keyHex is the key
   @return the ciphertext in a 4*4 matrix
   */
  protected static Integer[][] aes(String pTextHex, String keyHex) {

    //Stores the ciphertext
    Integer[][] cTextHex = new Integer[4][4];

    //Stores plaintext in a 4*4 Integer matrix
    Integer[][] Plaintext = StringToIntMatrix(pTextHex);

    //Stores the 11 round keys in a 44*4 matrix
    Integer[][] KeyArr = aesRoundKeys(keyHex);

    //Copying values from KeyArr to Keys
    for (int k = 0; k < 11; k++) {
      for (int i = 0; i < 4; i++) {
        System.arraycopy(KeyArr[(4 * k) + i], 0, Keys[k][i], 0, 4);
      }
    }
    //CTextRound stores 11 intermediate AES results in eleven 4*4 planes
    //(2D arrays)
    Integer[][][] CTextRound = new Integer[11][4][4];
    CTextRound[0] = transpose(aesStateXOR(Plaintext, Keys[0]));

    //Round 1 to 10 is done here
    for (int i = 1; i < 11; i++) {
      CTextRound[i] = oneRound(CTextRound[i - 1], i);
    }
    return transpose(CTextRound[10]);
  }
}
