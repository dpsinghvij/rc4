package crypto.rc4.sender;

import crypto.rc4.sender.cipher.RC4;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by davinder on 27/11/16.
 */
public class Test {

    public static void main(String[] args) {

        String key="0123456789ABCDEF";// "0x01230123";           // key for initialization of State Vector
        List<List<Byte>> encryptedPackets= new ArrayList<>();
        RC4 rc4= new RC4(key);
       // rc4.PRGAWithoutOutput();
        rc4.PRGAWithoutOutput();
        rc4.PRGAWithoutOutput();
        rc4.PRGAWithoutOutput();
        rc4.PRGAWithoutOutput();
        rc4.PRGAWithoutOutput();
    //    rc4.PRGAWithoutOutput(1);
        rc4.IPRGA();
        rc4.IPRGA();
        rc4.IPRGA();
        rc4.IPRGA();
        rc4.IPRGA();

        rc4.PRGAWithoutOutput();

    }
}
