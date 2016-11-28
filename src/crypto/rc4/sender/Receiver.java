package crypto.rc4.sender;

import crypto.rc4.sender.Utility.Constants;
import crypto.rc4.sender.Utility.Utils;
import crypto.rc4.sender.cipher.RC4;
import crypto.rc4.sender.models.MessagePacket;
import rx.Observable;
import rx.Subscriber;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Created by davinder on 27/11/16.
 */
public class Receiver {

    public static void main(String[] args) {
        // read input from encrypted
        List<Byte> encryptedText=new ArrayList<>();
        List<Byte> plaintext = null;
        String key="0123456789ABCDEF";// "0x01230123";           // key for initialization of State Vector
        List<List<Byte>> encryptedPackets= new ArrayList<>();
        //Long decode = Long.decode(key);
        byte[] keyByteArray= key.getBytes();//Utils.longToBytes(decode);
        int offset=0;
        try {
            byte[] encryptedBytes = Files.readAllBytes(Paths.get("encrypted"));//readEncryptedText();
            for (byte b :
                    encryptedBytes) {
                encryptedText.add(b);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (encryptedText.isEmpty()) {
            return;
        }
        offset= getOffset();
        RC4 rc4= new RC4(keyByteArray,offset);
        // divide it into 272 bytes packets
        int finalOffset = offset;
        List<List<Byte>> dividedEncryptedBytes= new ArrayList<>();
        Observable.from(encryptedText)
                .buffer(272)
                .subscribe(new Subscriber<List<Byte>>() {
                    @Override
                    public void onCompleted() {

                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onNext(List<Byte> bytes) {

                        dividedEncryptedBytes.add(bytes);
                       /* MessagePacket messagePacket = MessagePacket.decryptPacket(rc4, bytes, finalOffset);
                        if(messagePacket==null)
                            return;
                        byte[] msg= Utils.getByteListToArray(messagePacket.getData());
                        System.out.println(messagePacket.getSequenceCounter()+" "+new String(msg));*/

                    }
                });

        Collections.shuffle(dividedEncryptedBytes,new Random(30));
        for (List<Byte> bytes :
                dividedEncryptedBytes) {
            MessagePacket messagePacket = MessagePacket.decryptPacket(rc4, bytes, finalOffset);
            if(messagePacket==null)
                return;
            byte[] msg= Utils.getByteListToArray(messagePacket.getData());
            System.out.println(messagePacket.getSequenceCounter()+" "+new String(msg));
        }
        // save sc state in RC4
        // compare sc state
        // perform PRGA or IPRGA accordingly
        // decrypt each byte
        // calculate hash
        // check if hash calculated is equal to received hash
        // if same then show output
    }

    private static List<Byte> readEncryptedText() throws IOException {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("plaintext"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            String everything = sb.toString();
            byte[] bytes = everything.getBytes();
            List<Byte> byteList= new ArrayList<>();
            for (byte b :
                    bytes) {
                byteList.add(b);
            }
            return byteList;
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            br.close();
        }
        return null;
    }

    private static int getOffset() {
        return Constants.OFFSET;
    }
}
