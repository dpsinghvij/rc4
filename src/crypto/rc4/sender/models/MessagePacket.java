package crypto.rc4.sender.models;

import crypto.rc4.sender.Utility.Utils;
import crypto.rc4.sender.cipher.RC4;
import crypto.rc4.sender.cipher.RC4BHF;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by davinder on 26/11/16.
 */
public class MessagePacket {
    private int sequenceCounter;
    private List<Byte> sequenceCounterBytes;
    private List<Byte> data;
    private List<Byte> dataPacket;
    private List<Byte> hashValue;

    public MessagePacket(int sequenceCounter, List<Byte> dataSegment,int offset) {
        this.sequenceCounter = sequenceCounter;
        this.data = dataSegment;
        checkDataSegmentAndApplyPadding();
        sequenceCounterBytes= getIntBytes();
        List<Byte> hashingInput= new ArrayList<>();
        hashingInput.addAll(sequenceCounterBytes);
        hashingInput.addAll(dataSegment);
        RC4BHF rc4BHF= new RC4BHF(hashingInput,offset);
        hashValue= rc4BHF.hash();
        dataPacket = new ArrayList<>();
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

    public static MessagePacket decryptPacket(RC4 rc4,List<Byte> bytes, int offset){
        if(bytes.size()<272){
            return null;
        }
        MessagePacket messagePacket = new MessagePacket();
        List<Byte> scBytes= bytes.subList(0,4);
        ByteBuffer buffer= ByteBuffer.wrap(Utils.getByteListToArray(scBytes));
        messagePacket.sequenceCounter = buffer.getInt();
        List<Byte> dataPacketEncrypted=bytes.subList(4,272);
        rc4.adjustRC4State(messagePacket.sequenceCounter);
        List<Byte> decryptedPacket = rc4.PRGA(dataPacketEncrypted);
        messagePacket.data= decryptedPacket.subList(0,252);
        messagePacket.hashValue= decryptedPacket.subList(252,268);
        List<Byte> hashingInput= new ArrayList<>();
        hashingInput.addAll(scBytes);
        hashingInput.addAll(messagePacket.data);
        RC4BHF rc4BHF= new RC4BHF(hashingInput,offset);
        List<Byte> hash= rc4BHF.hash();
        boolean isMatch=true;
        for (int i = 0; i < hash.size(); i++) {
            if(!hash.get(i).equals(messagePacket.hashValue.get(i))){
                isMatch=false;
                break;
            }
        }
        if(isMatch){
            System.out.println("Hash Matched");
        }
        return messagePacket;
    }

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
