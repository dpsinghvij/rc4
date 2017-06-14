package crypto.rc4.sender.models;

import crypto.rc4.sender.Utility.Utils;
import crypto.rc4.sender.cipher.RC4;
import crypto.rc4.sender.cipher.RC4BHF;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by davinder on 26/11/16.
 * It is a class which deals with
 * a. padding of message data if less than 252
 * b. calculating hash value based on sequence counter and dataSegment
 * c. encrypts packet
 * d. decrypts packet & check hashing value
 */
public class MessagePacket {
    private int sequenceCounter;
    private List<Byte> sequenceCounterBytes;
    private List<Byte> data;
    private List<Byte> dataPacket;
    private List<Byte> hashValue;

    /**
     *
     * @param sequenceCounter sequence counter of the packet
     * @param dataSegment Data
     * @param offset offset for calculating RC4-BHF hash
     */
    public MessagePacket(int sequenceCounter, List<Byte> dataSegment,int offset) {
        this.sequenceCounter = sequenceCounter;
        this.data = dataSegment;
        checkDataSegmentAndApplyPadding();
        // get Sequence counter in bytes
        sequenceCounterBytes= getIntBytes();
        List<Byte> hashingInput= new ArrayList<>();
        // add sequenceCounterBytes and dataSegment for hashing
        hashingInput.addAll(sequenceCounterBytes);
        hashingInput.addAll(dataSegment);
        // Initialize RC4-BHF object
        RC4BHF rc4BHF= new RC4BHF(hashingInput,offset);
        // calculate hash
        hashValue= rc4BHF.hash();
        dataPacket = new ArrayList<>();
        // add data and hash in an array this will be encrypted
        dataPacket.addAll(dataSegment);
        dataPacket.addAll(hashValue);
    }

    public MessagePacket(){

    }

    public MessagePacket(List<Byte> bytes){
        List<Byte> scBytes= bytes.subList(0,4);
        ByteBuffer buffer= ByteBuffer.wrap(Utils.getByteListToArray(scBytes));
        sequenceCounter = buffer.getInt();
        List<Byte> dataPacketEncrypted=bytes.subList(4,272);
    }

    /**
     * Decrypts packet
     * @param rc4 RC4 object
     * @param bytes encrypted bytes
     * @param offset offset for calculation hashing function
     * @return decrypted message
     */
    public static MessagePacket decryptPacket(RC4 rc4,List<Byte> bytes, int offset){
        if(bytes.size()<272){
            return null;
        }
        MessagePacket messagePacket = new MessagePacket();
        // get first 4 bytes, which are Sequence Counter
        List<Byte> scBytes= bytes.subList(0,4);
        ByteBuffer buffer= ByteBuffer.wrap(Utils.getByteListToArray(scBytes));
        // convert sequenceCounter bytes to integer
        messagePacket.sequenceCounter = buffer.getInt();
        // get the list of encrypted bytes
        List<Byte> dataPacketEncrypted=bytes.subList(4,272);
        // adjust the RC4 states according to sequence counter
        rc4.adjustRC4State(messagePacket.sequenceCounter);
        // decrypt packet
        List<Byte> decryptedPacket = rc4.PRGA(dataPacketEncrypted);
        messagePacket.data= decryptedPacket.subList(0,252);
        messagePacket.hashValue= decryptedPacket.subList(252,268);
        List<Byte> hashingInput= new ArrayList<>();
        hashingInput.addAll(scBytes);
        hashingInput.addAll(messagePacket.data);
        RC4BHF rc4BHF= new RC4BHF(hashingInput,offset);
        // calculate hash
        List<Byte> hash= rc4BHF.hash();
        boolean isMatch=true;
        // if calculated hash matches with the received hash, it means data hasn't been changed
        for (int i = 0; i < hash.size(); i++) {
            if(!hash.get(i).equals(messagePacket.hashValue.get(i))){
                isMatch=false;
                break;
            }
        }
        if(isMatch){
            System.out.println("Hash Matched");
        }else {
            System.out.println("Warning!!!!! Hash Miss-Match");
        }
        return messagePacket;
    }

    /**
     * if data size is less than 252 than padding is applied
     */
    private void checkDataSegmentAndApplyPadding() {
        if (data == null) {
            return;
        }
        if(data.size()<252){

           data.add((byte) 0x80);
           while (data.size()<252){
               data.add((byte) 0x00);
           }
        }
    }

    /**
     * Converts integer to byte list
     * @return
     */
    private List<Byte> getIntBytes() {

        List<Byte> intBytes= new ArrayList<>();
        Byte byte0 = (byte) (sequenceCounter >> 24);
        Byte byte1 = (byte) (sequenceCounter >> 16);
        Byte byte2 = (byte) (sequenceCounter >> 8);
        Byte byte3 = (byte) (sequenceCounter /*>> 0*/);
        intBytes.add(byte0);
        intBytes.add(byte1);
        intBytes.add(byte2);
        intBytes.add(byte3);
        return intBytes;
    }

    /**
     * 268 bytes of data and hash are encrypted
     * @param rc4
     * @return
     */
    public List<Byte> encrypt(RC4 rc4) {
        List<Byte> encrytedBytes= new ArrayList<>();
        encrytedBytes.addAll(getIntBytes());
        List<Byte> prga = rc4.PRGA(dataPacket);
        encrytedBytes.addAll(prga);
        return encrytedBytes;
    }

    public int getSequenceCounter() {
        return sequenceCounter;
    }

    public List<Byte> getData() {
        return data;
    }

    public List<Byte> getHashValue() {
        return hashValue;
    }
}
