package crypto.rc4.sender;

import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;
import crypto.rc4.sender.Utility.Constants;
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
 */
public class Main {



    public static void main(String[] args) {
        List<Byte> plaintext = null;
        String key="0123456789ABCDEF";// "0x01230123";           // key for initialization of State Vector
        List<List<Byte>> encryptedPackets= new ArrayList<>();
        //Long decode = Long.decode(key);
        byte[] keyByteArray= key.getBytes();//Utils.longToBytes(decode);
         int offset=0;
        try {
            plaintext=getInput();
            offset= getOffset();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (plaintext == null) {
            return;
        }
        int finalOffset = offset;
        RC4 rc4= new RC4(keyByteArray,offset);
        List<MessagePacket> packets= new ArrayList<>();
        Observable.from(plaintext)
                  .buffer(Constants.PACKET_SIZE)
                  .subscribe(new Subscriber<List<Byte>>() {
                      int sequenceCounter=0;
                      @Override
                      public void onCompleted() {
                            ;
                          byte[] result = new byte[encryptedPackets.size()*272];
                          for(int i = 0; i < encryptedPackets.size(); i++) {
                              List<Byte> encryptedPacket= encryptedPackets.get(i);
                              for (int j = 0; j < encryptedPacket.size(); j++) {
                                  result[i*272+j]= encryptedPacket.get(j);
                              }
                          }
                    //      System.out.println(new String(result));
                          try {
                              FileOutputStream  out = new FileOutputStream("encrypted");
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

                          MessagePacket messagePacket= new MessagePacket(sequenceCounter++,
                                  bytes, finalOffset);
                          packets.add(messagePacket);
                          List<Byte> encryptedPacket = messagePacket.encrypt(rc4);
                          encryptedPackets.add(encryptedPacket);

                      }
                  });



    }

    private static int getOffset() {
        return Constants.OFFSET;
    }

    private static List<Byte> getInput() throws IOException {
        /*ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        URL resUrl = classLoader.getResource("plaintext");
        if (resUrl == null) {
            return null;
        }
        String plaintext = resUrl.getFile();
        File file = new File(plaintext);
        StringBuilder result= new StringBuilder();
        try (Scanner scanner = new Scanner(file)) {

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                result.append(line).append("\n");
            }

            scanner.close();

        } catch (IOException e) {
            e.printStackTrace();
        }*/

        BufferedReader br = new BufferedReader(new FileReader("plaintext"));
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
}
