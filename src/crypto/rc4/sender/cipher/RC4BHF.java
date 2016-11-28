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

    private List<Byte> generateMsgOfBytes(int count) {
        List<Byte> templist= new ArrayList<>();
        for (int i = 0; i < count; i++) {
            byte b= (byte) ((i+20)%256);
            templist.add(b);
        }
        return templist;
    }

    public List<Byte> hash(){
        appendAndDivideMsg();
        return compressionAndOutput();
    }
    public void appendAndDivideMsg(){
        //msgList = new ArrayList<Byte>(Arrays.asList(msg));
        // find length of msg
        int msgLength= msgList.size();
        if(msgLength>65536){
            System.err.println("length can't be greater than ");
            return;
        }
        // Check if (number of bytes of msg+3) is divisible by 64
        int divCount= (msgLength+3)/64;
        int lastPacketByteCount = msgLength%64;
        int zerobyteCount= 0;
        List<Byte> arrayListOfZeros;
        List<Byte> lengthInBytes;
        Byte deLimiter= (byte)0x80;
        // 1 byte for 1 delimiter , last 2 bytes for count
        switch (64-lastPacketByteCount){

            case 1:
                // count of zeros to be added
                zerobyteCount= 64-2;
                break;
            case 2:
                zerobyteCount= 64-1;
                break;
            default:
                zerobyteCount=  64- lastPacketByteCount-3;
                break;
        }
        addPaddingAndDelimiter(msgList, zerobyteCount);
        Observable.from(msgList)
                .buffer(64)
                .subscribe(new Action1<List<Byte>>() {
                    @Override
                    public void call(List<Byte> bytes) {
                        dividedMsgList.add(bytes);
                    }
                });
      //  System.out.println(dividedMsgList.size());
      //  showMsgListWithPadding();
        compressionAndOutput();
    }

    private List<Byte> compressionAndOutput(){
        List<Byte> stateList= new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            stateList.add((byte) i);
        }
        if(dividedMsgList.isEmpty())
            return null;

        List<Byte> message = dividedMsgList.get(0);
        ksa(stateList, message);
        prga(stateList,offset);
        prga(stateList,getLength(message,offset));
        for (int i = 1; i < dividedMsgList.size(); i++) {
            List<Byte> messageI = dividedMsgList.get(i);
            ksa(stateList, messageI);
            prga(stateList,getLength(messageI,offset));
        }

        // output
        List<Byte> stateListKSA= new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            stateListKSA.add((byte) i);
        }
        ksa(stateListKSA,stateList);
        List<Byte> bytes = prgaWithOutput(stateListKSA, 512);
        List<Byte> outIntermidiate= new ArrayList<>();
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
        return hashArray;
    }
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

    private void addPaddingAndDelimiter(List<Byte> msgList, int zerobyteCount) {
        int msgLength= msgList.size();
        List<Byte> arrayListOfZeros;
        List<Byte> lengthInBytes;
        Byte deLimiter= (byte)0x80;
        arrayListOfZeros = getArrayListOfZeros(zerobyteCount);
        msgList.add(deLimiter);
        msgList.addAll(arrayListOfZeros);
        // last two bytes will have size of the
        lengthInBytes = getLengthInBytes(msgLength);
        msgList.addAll(lengthInBytes);
    }

    private List<Byte> getLengthInBytes(int msgLength) {
        byte firstByte= (byte) (msgLength & 0xff);
        byte secondByte= (byte) (msgLength>>>8 & 0xff);
        List<Byte> numberBytes= new ArrayList<>();
        numberBytes.add(secondByte);
        numberBytes.add(firstByte);
        return numberBytes;
    }

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

    private void prga(List<Byte> messageK,int offset){

        int i=0,j=0;
        int n=0;
        byte k;
        while (n<offset){

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

    private List<Byte> prgaWithOutput(List<Byte> messageK, int offset){

        int i=0,j=0;
        int n=0;
        byte k;
        List<Byte> prgaOutput= new ArrayList<>();
        while (n<offset){

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

    private int getModOfMessage(List<Byte> message){
        int sumOfMod = 0;
        for (Byte b :
                message) {
            int value= b&0xff;
            sumOfMod+= value;
        }
        return sumOfMod%256;
    }

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
        return modOfMessage ==0?offset:modOfMessage;
    }

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
