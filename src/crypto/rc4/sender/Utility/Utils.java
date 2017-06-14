package crypto.rc4.sender.Utility;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by davinder on 16/10/16.
 */
public class Utils {

 //   private static ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

    public static String toHex(String arg) {
        return String.format("%x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
    }


    /**
     * Convert long type to byte array
     * @param x input long value
     * @return byte array
     */
    public static byte[] longToBytes(long x) {
      //  buffer.putLong(0, x);
        return ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(x).array();
    }

    public static byte[] getByteListToArray(List<Byte> byteList){
        byte[] result = new byte[byteList.size()];
        for (int i = 0; i < byteList.size(); i++) {
            result[i]= byteList.get(i);
        }
        return result;
    }
  /*  public static long bytesToLong(byte[] bytes) {
        buffer.put(bytes, 0, bytes.length);
        buffer.flip();//need flip
        return buffer.getLong();
    }*/

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }


    /**
     * checks if key is in hexadecimal or string and returns corresponding bytearray
     * @param key key string
     * @return byte array of key
     */
    public static byte[] processKey(String key){
        if(key.substring(0,2).equals("0x")){
            try {
                /*Long decode = Long.decode(key);
                return Utils.longToBytes(decode);*/
                key= key.substring(2);
                return toByteArray(key);
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }
        }
        return key.getBytes();
    }

    public static List<Byte> removePadding(List<Byte> packet){
        int byteCount=0;
        List<Byte> padding= new ArrayList<>();
        for (int i = packet.size()-1; i >=0 ; i--) {
            Byte aByte = packet.get(i);
            if(aByte == 0x00){
                byteCount++;
                // padding bytes are added in padding array
                padding.add(aByte);
            }else {
                // 128 here signifies 0x80
                if((aByte&0xff)==128){
                    padding.add(aByte);
                    // padding is removed from the packet
                    packet.removeAll(padding);
                    return packet;
                }else {
                    return packet;
                }
            }

        }
        return packet;
    }
}
