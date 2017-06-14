package crypto.rc4.sender;

import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;
import crypto.rc4.sender.Utility.Constants;
import crypto.rc4.sender.Utility.InputHelper;
import crypto.rc4.sender.Utility.Utils;
import crypto.rc4.sender.cipher.RC4;
import crypto.rc4.sender.models.MessagePacket;
import rx.Observable;
import rx.Subscriber;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Created by davinder on 25/11/16.
 * This is implementation of sender interface.
 * It takes key, Plain text and offset as input
 * and encrypts data into text file encrypted
 */
public class Main {


    public static void main(String[] args) {
        List<Byte> plaintext = null;
        String key = InputHelper.readKey();   // key taken as input from user

        //Long decode = Long.decode(key);
        // key is converted to byte array
        byte[] keyByteArray = Utils.processKey(key);//Utils.longToBytes(decode);
        // offset is used for RC4-BHF function
        int offset = 0;
        plaintext = getInput();
        // offset is taken as input from console
        offset = InputHelper.readOffset();
        if (plaintext == null) {
            return;
        }
        final int finalOffset = offset;
        // RC4 object is initialized
        final RC4 rc4 = new RC4(keyByteArray);

        // Plaintext is read in a packets 252 bytes
        Observable.from(plaintext)
                .buffer(Constants.PACKET_SIZE)
                .subscribe(new Subscriber<List<Byte>>() {
                    int sequenceCounter = 0;
                    List<MessagePacket> packets = new ArrayList<>();
                    List<List<Byte>> encryptedPackets = new ArrayList<>();
                    @Override
                    public void onCompleted() {
                        ;
                        byte[] result = new byte[encryptedPackets.size() * 272];
                        for (int i = 0; i < encryptedPackets.size(); i++) {
                            List<Byte> encryptedPacket = encryptedPackets.get(i);
                            for (int j = 0; j < encryptedPacket.size(); j++) {
                                result[i * 272 + j] = encryptedPacket.get(j);
                            }
                        }
                        //      System.out.println(new String(result));
                        System.out.println("Data encrypted successfully!!!!");
                        // encrypted bytes are written in a file
                        try {
                            FileOutputStream out = new FileOutputStream("encrypted");
                            out.write(result);
                            out.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

                    @Override
                    public void onError(Throwable e) {
                        e.printStackTrace();
                    }

                    @Override
                    public void onNext(List<Byte> bytes) {
                        // Message packet object is initialized
                        MessagePacket messagePacket = new MessagePacket(sequenceCounter++,
                                bytes, finalOffset);
                        // message is added in packet
                        packets.add(messagePacket);
                        // message is encrypted
                        List<Byte> encryptedPacket = messagePacket.encrypt(rc4);
                        // encrypted packet is added in a list
                        encryptedPackets.add(encryptedPacket);

                    }
                });


    }


    /**
     * Input is taken from user and value is converted in byte array
     * @return plain text in byte array
     */
    private static List<Byte> getInput() {
        // console input
        String inputMessage = InputHelper.readMessage();
        if (inputMessage == null) {
            return null;
        }
        // string is converted to byte array
        byte[] bytes = inputMessage.getBytes();
        List<Byte> byteList = new ArrayList<>();
        for (byte b :
                bytes) {
            byteList.add(b);
        }
        return byteList;
    }


}
