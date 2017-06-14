package crypto.rc4.sender.Utility;

import java.util.Scanner;

/**
 * Created by davinder on 29/11/16.
 */
public class InputHelper {

    public static String readMessage(){
        Scanner scanner= new Scanner(System.in);
        print("Please Enter Message to be Encrypted");
        return scanner.nextLine();
    }

    public static String readKey(){
        Scanner scanner= new Scanner(System.in);
        print("Please Enter Key for encryption (Please add '0x' at start of key if it is in hexadecimal)");
        return scanner.next();
    }

    public static int readOffset(){
        Scanner scanner= new Scanner(System.in);
        print("Please enter offset, This will be used for Hash function");
        return scanner.nextInt();
    }

    public static int readTestCase(){
        Scanner scanner= new Scanner(System.in);
        print("Please enter your test case number\n" +
                "1: the sequence of the packets received is 0, 1, 2 and 3\n" +
                "2: the sequence of the packet received is 1, 0, 3 and 2\n" +
                "3: the sequence of the packet received is 3, 2, 1 and 0\n" +
                "4: input message is 1800 bytes long, sent in increased order");
        return scanner.nextInt();
    }
    private static void print(String message){
        System.out.println(message);
    }
}
