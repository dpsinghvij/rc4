package crypto.rc4.sender.cipher;

/*
 * Created by davinder on 24/11/16.
 */




import com.sun.deploy.util.ArrayUtil;
import rx.Observable;
import rx.functions.Action1;

import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.swap;

/**
 * This class has implementation of Hashing function RC4-BHF, an RC4 based hash function.
 * The input of RC4-BHF could be any message with a maximum length of 65536 bits or  8192 bytes.
 * It is used for integrity check of the encrypted byte
 *
 */
public class RC4BHF {

    public static final int COUNT = 67;
    public static final int OFFSET=10;
    private Byte[] msg;
    List<Byte> msgList;
    List<List<Byte>> dividedMsgList;
    int offset;
    public RC4BHF(byte[] msg, int offset) {

        msgList = new ArrayList<Byte>();
        for (byte aMsg : msg) {
            msgList.add(aMsg);
        }
        dividedMsgList= new ArrayList<>();
        this.offset=offset;
    }

    /**
     * Initialize class with the message for which hash function is to be calculated and
     * offset
     * @param msgs message for hash function is to be calculated
     * @param offset it determines how many time PRGA will run
     */
    public RC4BHF(List<Byte> msgs, int offset) {

        msgList = msgs;
        dividedMsgList= new ArrayList<>();
        this.offset=offset;
    }

    public RC4BHF() {
        this.msgList = generateMsgOfBytes(COUNT);
        offset=OFFSET;
        dividedMsgList= new ArrayList<>();
    }

    /**
     * Used for test purpose, to generate a message of hashing
     * @param count length of message
     * @return
     */
    private List<Byte> generateMsgOfBytes(int count) {
        List<Byte> templist= new ArrayList<>();
        for (int i = 0; i < count; i++) {
            byte b= (byte) ((i+20)%256);
            templist.add(b);
        }
        return templist;
    }

    /**
     * It calculates the hash function using 3 steps
     * 1. Append Padding Bits and Length, and Divide the Padded Message
     * 2. Compression
     * 3. Output Processing
     * @return
     */
    public List<Byte> hash(){
        // appends padding bits and length and then divides it in different packets
        appendAndDivideMsg();
        // Compresses and gives output
        return compressionAndOutput();
    }

    /**
     * appends padding bits and length and then divides it in different packets.
     * As length of message can max be 65536 which could be represented by 2^16. So we need
     * 16 bits i.e 2 bytes to store length of the message.
     *
     *
     */
    public void appendAndDivideMsg(){
        //msgList = new ArrayList<Byte>(Arrays.asList(msg));
        // find length of msg
        int msgLength= msgList.size();
        // if size is greater than 8192 bytes of 65536 bits than stop
        if(msgLength>8192){
            System.err.println("length can't be greater than ");
            return;
        }
        //  find the number of bytes in last packet, note that each packet is of 64 byte
        int lastPacketByteCount = msgLength%64;
        int zerobyteCount= 0;
        // 1 byte for 1 delimiter , last 2 bytes for count
        switch (64-lastPacketByteCount){ // check how many bytes are needed to complete a packet

            case 1:// this case means last packet has 63 bytes, so we would need to add a
                // 1 byte of padding, 62 bytes of zeros and length(2 bytes)
                // count of zeros to be added
                zerobyteCount= 64-2;
                break;
            case 2:
                // this case means last packet has 62 bytes, so we would need to add a
                // 1 byte of padding, 63 bytes of zeros and length(2 bytes)
                // count of zeros to be added
                zerobyteCount= 64-1;
                break;
            default:
                // this case means last packet has 61 or less bytes, so we would need to add a
                // 1 byte of padding, 2 bytes for length and rest as zeroes
                // count of zeros to be added
                zerobyteCount=  64- lastPacketByteCount-3;
                break;
        }
        // this adds padding and delimiter according to the zeroes count
        addPaddingAndDelimiter(msgList, zerobyteCount);
        // divide msglist in equal 64 bytes chunks
        Observable.from(msgList)
                .buffer(64)
                .subscribe(new Action1<List<Byte>>() {
                    @Override
                    public void call(List<Byte> bytes) {
                        // all bytes are added in an array of bytes
                        dividedMsgList.add(bytes);
                    }
                });
        //
      //  compressionAndOutput();
    }

    /**
     * It is divided in two steps compression and output.
     * In compression, KSA and PRGA is performed on the divided message bytes
     * In output, the output of compression state is fed to a ksa and Prga. The right 256 bytes
     * output of PRGA is X-Ored with State output from compression step. Then data is reduced
     * to get hash
     * @return hash value for the input message
     */
    private List<Byte> compressionAndOutput(){
        List<Byte> stateList= new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            stateList.add((byte) i);
        }
        if(dividedMsgList.isEmpty())
            return null;

        // take the first message byte, m1
        List<Byte> message = dividedMsgList.get(0);
        // apply Ksa using m1 as key
        ksa(stateList, message);
        // use the user input offset as length, number of times prga should be run
        prga(stateList,offset);
        // run prga again this time length length will be decided using a process
        prga(stateList,getLength(message,offset));
        // for rest of Message bytes perform KSA and PRGA
        for (int i = 1; i < dividedMsgList.size(); i++) {
            List<Byte> messageI = dividedMsgList.get(i);
            ksa(stateList, messageI);
            prga(stateList,getLength(messageI,offset));
        }

        // -----------------------------OUTPUT STEP BEGINS HERE ---------------------------------------------
        // Initialize KSA states
        List<Byte> stateListKSA= new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            stateListKSA.add((byte) i);
        }
        // KSA is run using Compression output as key for KSA
        ksa(stateListKSA,stateList);
        // Run PRGA 512 times and get rightmost 256 bytes of PRGA output
        List<Byte> bytes = prgaWithOutput(stateListKSA, 512);
        List<Byte> outIntermidiate= new ArrayList<>();
        // X-or Compress state output with , prga output
        for (int i = 0; i < 256; i++) {
            byte b= (byte) (stateList.get(i) ^ bytes.get(i));
            outIntermidiate.add(b);
        }

        // iterate through byte array;
        int bitCounter=8;
        byte hashByte = 0x00;
        List<Byte> hashArray=new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            // check for odd location/ even for array index

            if(i%2==0){
                // Get byte from output
                byte byteConsidered= outIntermidiate.get(i);
                // read the last bit of the byte
                byte lastBit= (byte) (byteConsidered&0x01);
                hashByte = (byte) (hashByte | (lastBit << bitCounter));
                bitCounter--;
                if(bitCounter==0){
                    hashArray.add(hashByte);
                    hashByte=0x00;
                    bitCounter=8;

                }
            }
        }
        //showHash(hashArray);
        // return the hash calculated
        return hashArray;
    }

    /**
     * A function used for testing purpose for debugging
     */
    private void showMsgListWithPadding() {
        StringBuilder stringBuilder= new StringBuilder();
        int i=1;
        System.out.println(msgList.size());
        for (Byte b :
                msgList) {

            stringBuilder.append(String.format("%02X ", b));
            if(i==COUNT){
                stringBuilder.append("DEL");
            }
            stringBuilder.append(i).append(" ");
            i++;
        }
        System.out.println(stringBuilder.toString());
    }

    /**
     * Helper method to add '1' delimiter , zeroes and length L
     * @param msgList  message bytes
     * @param zerobyteCount number of zeroes to be added
     */
    private void addPaddingAndDelimiter(List<Byte> msgList, int zerobyteCount) {
        int msgLength= msgList.size();
        List<Byte> arrayListOfZeros;
        List<Byte> lengthInBytes;
        // 0x80 in binary representation is written as 10000000
        Byte deLimiter= (byte)0x80;
        // create an arraylist of zeros, which will be used for padding
        arrayListOfZeros = getArrayListOfZeros(zerobyteCount);
        // first we add delimiter
        msgList.add(deLimiter);
        // all the zeros are added in the arrayList
        msgList.addAll(arrayListOfZeros);
        // last two bytes will have size of the message
        lengthInBytes = getLengthInBytes(msgLength);
        // a processed message is updated
        msgList.addAll(lengthInBytes);
    }

    /**
     * Return length of message in bytes. This used to append at the
     * end of message
     * @param msgLength size of message
     * @return result in bytes
     */
    private List<Byte> getLengthInBytes(int msgLength) {
        byte firstByte= (byte) (msgLength & 0xff);
        byte secondByte= (byte) (msgLength>>>8 & 0xff);
        List<Byte> numberBytes= new ArrayList<>();
        numberBytes.add(secondByte);
        numberBytes.add(firstByte);
        return numberBytes;
    }

    /**
     * Key schedule algorithm of RC4
     * @param state A 256 bytes array
     * @param messageK a key for scheduling of RSA
     */
    private void ksa(List<Byte> state,List<Byte> messageK){
        int j=0;
        // this keylength will give flexibility
        // we would not be required to give any input in this file
        //
        int keyLength= messageK.size();
        for (int i = 0; i < 256; i++) {
            j= (j+ state.get(i)&0xff+ (messageK.get(i%keyLength)&0xff))%256;
            swap(state,i,j);
        }
    }

    /**
     *
     * function used for Psuedo Random Generation of Key stream. Here
     * Keystream k is generated which is used of encryption

     * @param messageK input key
     * @param numberOfRuns number of times prga has to be executed
     */
    private void prga(List<Byte> messageK,int numberOfRuns){

        int i=0,j=0;
        int n=0;
        byte k;
        while (n<numberOfRuns){

            i=(i+1)%256;
            // Java doesn't have unsigned byte, that means it can save values from -128 to 127
            // So I solution to get values greater than 127
            // we AND byte with 0xff, to get its value
            j= (j+messageK.get(i)&0xff)%255;
            swap(messageK,i,j);
            n++;
        }
   //     System.out.println("Starting IPRGA");
        //       IPRGA(state,i,j,n-1);
    }

    /**
     * function used for Psuedo Random Generation of Key stream. Here
     * Keystream k is generated which is used of encryption
     * @param messageK input state
     * @param numberOfRuns number of times prga has to be executed
     * @return accumulated byte output of PRGA
     */
    private List<Byte> prgaWithOutput(List<Byte> messageK, int numberOfRuns){

        int i=0,j=0;
        int n=0;
        byte k;
        List<Byte> prgaOutput= new ArrayList<>();
        while (n<numberOfRuns){

            i=(i+1)%256;
            // Java doesn't have unsigned byte, that means it can save values from -128 to 127
            // So I solution to get values greater than 127
            // we AND byte with 0xff, to get its value
            j= (j+messageK.get(i)&0xff)%255;
            swap(messageK,i,j);
            n++;
            int t= (messageK.get(i)&0xff+messageK.get(j)&0xff)%256;
            k= messageK.get(t);
            if(n>256){
                prgaOutput.add(k);
            }
        }
//        System.out.println("Starting IPRGA");
        return prgaOutput;
        //       IPRGA(state,i,j,n-1);
    }

    /**
     * Get Mod of a 64 byte message
     * @param message message
     * @return mod value
     */
    private int getModOfMessage(List<Byte> message){
        int sumOfMod = 0;
        for (Byte b :
                message) {
            int value= b&0xff;
            sumOfMod+= value;
        }
        // mod by 256
        return sumOfMod%256;
    }

    /**
     * Creates an arraylist filled with zero
     * @param zerobyteCount number of bytes with zeros that should be added in arraylist
     * @return
     */
    private List<Byte> getArrayListOfZeros(int zerobyteCount) {
        List<Byte> zeroByteList= new ArrayList<>();
        for(int i=0;i<zerobyteCount;i++){
            Byte b= 0x00;
            zeroByteList.add(b);
        }
        return zeroByteList;
    }

    private int getLength(List<Byte> message,int offset){
        int modOfMessage = getModOfMessage(message);
        // modOfMessage is zero then offset is used otherwise ModOfMessage is used for
        // number of rows
        return modOfMessage ==0?offset:modOfMessage;
    }

    /**
     * Testing function used for showing output
     * @param msgList bytes
     */
    private void showHash(List<Byte> msgList) {
        StringBuilder stringBuilder= new StringBuilder();
        int i=1;
        System.out.println(msgList.size());
        for (Byte b :
                msgList) {

            stringBuilder.append(String.format("%02X ", b));

            stringBuilder.append(i).append(" ");
            i++;
        }
        System.out.println(stringBuilder.toString());
    }
}
