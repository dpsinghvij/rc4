package crypto.rc4.sender.Utility;

import java.math.BigInteger;
import java.nio.ByteBuffer;
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
}
