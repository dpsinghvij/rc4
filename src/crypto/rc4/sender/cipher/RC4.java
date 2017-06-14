package crypto.rc4.sender.cipher;


import crypto.rc4.sender.Utility.Constants;
import crypto.rc4.sender.models.RC4State;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.swap;

/**
 * Created by davinder on 16/10/16.
 * Implementation of RC4 cipher
 *
 */
public class RC4 {
    private List<Byte> state = new ArrayList<>();    // state vector
    private List<Byte> t= new ArrayList<>();    // temporary vector to repeat key if keyLength is less than 256
    private byte[] key;                 // key used for encryption
    private int keyLength;              // length of the key
  //  private List<RC4State> forwardStateList, backwardStateList; // to save forward as well as backward RC4 state list in an array
    private String log= "%d. S is %s with i=%d and j= %d "; // String to show output
    private int numberOfRounds;         // number of rounds PRGA/IPRGA should run
    private int i=0,j=0;
    private int sequenceCounter;        // this maintains the current SequenceCounter of the RC4
    private PrintWriter writer;

    /**
     *
     * @param key Key for encryptiion
     *
     */
    public RC4(byte[] key) {
        intialize(key);
    }

    /**
     * This method initializes Temporary Vector t and initial permutation of State Vector
     * @param key key for encryption
     */
    private void intialize(byte[] key) {

        try {
            writer = new PrintWriter("prgaoutput", "UTF-8");
        } catch (FileNotFoundException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        //initialize key
        this.key= key;
        // set length of key
        keyLength = key.length;
        // initialize state
        for(int i=0;i<256;i++){
            // state vector is initialized with variable from 0-255
            state.add((byte) i);
            // length of key could be less than 256, so key is repeated in temporary vector t
            t.add(key[i% keyLength]);;
        }
        // Initial Permutation of the state vector
        ksa();
    }


    public RC4(String key){
        byte[] bytes = key.getBytes();
        intialize(bytes);
    }

    /**
     * function used for Psuedo Random Generation of Key stream. Here
     * Keystream k is generated which is used of encryption
     */
    public List<Byte> PRGA(List<Byte> messagePacket){


        int n=0;
        byte k;
        //displayOutput(i, j);
        List<Byte> outputBytes= new ArrayList<>();
        while (n<messagePacket.size()){

            i=(i+1)%256;
            // Java doesn't have unsigned byte, that means it can save values from -128 to 127
            // So solution to get values greater than 127
            // we AND byte with 0xff, to get its value
            j= (j+state.get(i)&0xff)%256;
            swap(state,i,j);
            int t= (state.get(i)&0xff+state.get(j)&0xff)%256;
            k= state.get(t);
            byte outputByte= (byte) (k ^ messagePacket.get(n));
            outputBytes.add(outputByte);
            n++;
            //displayOutput(this.i, j);
        }
        sequenceCounter++;
 //       displayOutput(this.i, j);
//        System.out.println("Starting IPRGA");
        return outputBytes;
 //       IPRGA(state,i,j,n-1);
    }

 /*   public void PRGAWithoutOutput(int packets){


        int n=0;
        byte k;

        while (n<packets* Constants.ENCRYPTED_PACKET_SIZE){

            i=(i+1)%256;
            // Java doesn't have unsigned byte, that means it can save values from -128 to 127
            // So I solution to get values greater than 127
            // we AND byte with 0xff, to get its value
            j= (j+state.get(i)&0xff)%256;
            swap(state,i,j);
            n++;
            int t= (state.get(i)&0xff+state.get(j)&0xff)%256;
            k= state.get(t);
            displayOutput(this.i, j);
            *//*byte outputByte= (byte) (k ^ messagePacket.get(this.i));
            messagePacket.add(outputByte);
            *//*
        }
        sequenceCounter+=packets;
    //    displayOutput(i, j);
        System.out.println("Starting IPRGA");
        //       IPRGA(state,i,j,n-1);
    }

    *//**
     * runs a loop in which we iterate to get back previous RC4
     * State using current RC4 state
     *//*
    public void IPRGA(int fromSC, int toSC){

        int diffSC= toSC-fromSC;     // current round
        diffSC= diffSC<0?-diffSC:diffSC;
        int dataPacketCtr= diffSC*Constants.ENCRYPTED_PACKET_SIZE;
   //     displayOutput(i, j);
        // loop for iteration
        int itr=1;
        while (itr<dataPacketCtr){
            *//*i=i&0xff;
            j=j&0xff;*//*
            swap(state,i,j);
            j= (j-state.get(i)&0xff +256)%256;
            i= ((i-1)+256)%256;
           displayOutput(i, j);
            itr++;
        }

        sequenceCounter-=diffSC;
        //displayOutput(i,j);
    }*/

    /**
     * displays formatted output
     * @param i
     * @param j
     */
    private void displayOutput(int i, int j) {
        StringBuilder sb = new StringBuilder();
        for (byte b : state) {
            sb.append(String.format("%02X ", b));           // converts byte to hexadecimal
        }
        String format = String.format(log,sequenceCounter,sb, i, j);
        writer.println(format);
        writer.flush();
      //  System.out.println(format);
    }

    /**
     * This function helps in initializing the
     * state vector. Here t (temporary vector) is used to produce initial permutation of
     * state.
     */
    private void ksa(){
        int j=0;
        for (int i = 0; i < 256; i++) {
            j= (j+ state.get(i)&0xff+ t.get(i)&0xff)%256;
            swap(state,i,j);
        }
    }

    /**
     * This function takes back the state array to the state of previous
     * Sequence counter. It accomplishes this by running loop for 268 times
     */
    public void IPRGA(){

        int dataPacketCtr= Constants.ENCRYPTED_PACKET_SIZE;
       /* System.out.println("Initial state  \\|/");
        displayOutput(i, j);*/
        // loop for iteration
        int itr=0;
        // counter is executed for 268 times so that it can be switched to previous
        // Sequence Counter state
        while (itr<dataPacketCtr){

            swap(state,i,j);
            j= (j-state.get(i)&0xff +256)%256;
            i= ((i-1)+256)%256;
            //   displayOutput(i, j);
            itr++;
        }
        // decrease global sequence counter by 1
        sequenceCounter--;
        displayOutput(i,j);
    }

    /**
     * This function brings forward the state of State array by 1 Sequence Counter.
     * It accomplishes this by running loop for 268 times
     */
    public void PRGAWithoutOutput(){


        int n=0;
        byte k;
        // counter is executed for 268 times so that it can be switched to previous
        // Sequence Counter state
        while (n<Constants.ENCRYPTED_PACKET_SIZE){

            i=(i+1)%256;
            // Java doesn't have unsigned byte, that means it can save values from -128 to 127
            // So I solution to get values greater than 127
            // we AND byte with 0xff, to get its value
            j= (j+state.get(i)&0xff)%256;
            swap(state,i,j);
            n++;
            int t= (state.get(i)&0xff+state.get(j)&0xff)%256;
            k= state.get(t);
            //  displayOutput(this.i, j);
            /*byte outputByte= (byte) (k ^ messagePacket.get(this.i));
            messagePacket.add(outputByte);
            */
        }
        // sequence counter is increased by 1
        sequenceCounter+=1;
        displayOutput(i, j);

        //       IPRGA(state,i,j,n-1);
    }


    /**
     * Compares RC4 sequence counter with the Sequence Counter of the received packet,
     * if difference is greater than zero then IPRGA is called
     * if difference is less than zero then PRGA is called
     * if difference=0 then nothing is done
     * @param sCtr Sequence Counter of the received packet
     */
    public void adjustRC4State(int sCtr){
        int diff= sequenceCounter-sCtr;
        if(diff>0){
            // Sequence counter of RC4 object is forward so we have to
            // bring it back
            // IPRGA(sequenceCounter,sCtr);
            for (int k = 0; k < diff; k++) {
                IPRGA();
            }
        }else if(diff<0){
            // Sequence counter of RC4 object is back so we have to
            // bring it forward by difference
            //  PRGAWithoutOutput(-diff);
            for (int k = 0; k < -diff; k++) {
                PRGAWithoutOutput();
            }
        }
        //  sequenceCounter=sCtr;
    }

}
