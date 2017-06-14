package crypto.rc4.sender;

import crypto.rc4.sender.Utility.Constants;
import crypto.rc4.sender.Utility.InputHelper;
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
 * This is implementation of receiver interface.
 * It takes key and offset as input
 * and decrypts data
 */
public class Receiver {

    public static void main(String[] args) {


        List<Byte> encryptedText=new ArrayList<>();
        List<Byte> plaintext = null;
        // read key from console
        String key = InputHelper.readKey();// "0x01230123";           // key for initialization of State Vector
        List<List<Byte>> encryptedPackets= new ArrayList<>();
        //Long decode = Long.decode(key);
        // convert key into byte array
        final byte[] keyByteArray = Utils.processKey(key);
        int offset=0;
        final int testCase;
        try {
            // read encrypted data from text file
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
        // read offset from console
        offset = InputHelper.readOffset();
        // read the selected test case
        testCase= InputHelper.readTestCase();
        // divide it into 272 bytes packets
        final int finalOffset = offset;
        Observable.from(encryptedText)
                .buffer(272)
                .subscribe(new Subscriber<List<Byte>>() {
                    List<List<Byte>> dividedEncryptedBytes= new ArrayList<>();
                    RC4 rc4= new RC4(keyByteArray);

                    @Override
                    public void onCompleted() {

                        // arrange the data according to the case
                        List<List<Byte>> arrangedEncryptedPackets = arrangePackets(dividedEncryptedBytes, testCase);
                        for (List<Byte> bytes :
                                arrangedEncryptedPackets) {
                            // decrypt data
                            MessagePacket messagePacket = MessagePacket.decryptPacket(rc4, bytes, finalOffset);
                            if(messagePacket==null)
                                return;
                            List<Byte> data = messagePacket.getData();
                            // Padding is removed if present and List is converted into byte array
                            byte[] msg= Utils.getByteListToArray(Utils.removePadding(data));
                            // show output in form of string
                            System.out.println(messagePacket.getSequenceCounter()+" "+new String(msg));
                        }
                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onNext(List<Byte> bytes) {
                        dividedEncryptedBytes.add(bytes);
                    }
                });


    }

    /**
     * Arrange Packets according to the input test case
     * @param dividedEncryptedBytes Encrypted bytes
     * @param i test case index
     * @return arranged Encrypted Bytes
     */
    private static List<List<Byte>>  arrangePackets(List<List<Byte>> dividedEncryptedBytes, int i) {
        List<List<Byte>> reArrangedEncryptedBytes= new ArrayList<>();
        switch (i){
            case 1:
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(0));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(1));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(2));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(3));
                break;
            case 2:
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(1));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(0));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(3));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(2));
                break;
            case 3:
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(3));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(2));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(1));
                reArrangedEncryptedBytes.add(dividedEncryptedBytes.get(0));
                break;
            case 4:
                reArrangedEncryptedBytes=dividedEncryptedBytes;
                break;
            default:
                Collections.shuffle(dividedEncryptedBytes);
                reArrangedEncryptedBytes=dividedEncryptedBytes;
                break;

        }
        return reArrangedEncryptedBytes;
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
