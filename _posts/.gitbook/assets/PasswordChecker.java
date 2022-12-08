
import java.util.*;

class PasswordChecker {
    public static void main (String []args){
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter password: ");
        String inp = sc.next();
        sc.close();
        if (!inp.startsWith("W1{") || !inp.endsWith("}")){
            System.out.println("Incorrect format!");
            System.out.println("You must put your password in `W1{}` format.");
            return;
        }
        if (inp.length()!=0x2a){
            System.out.print("Wrong length!");
            return;
        }
        inp = inp.substring(3,inp.length()-1);
        System.out.print(inp);
        if (checkPassword(inp)) {
            System.out.println("Access granted!");
        } else {
            System.out.println("Access denied!");
            }
        sc.close();
    }
    public static boolean checkPassword(String password){
        int []arr = {0xeb05,0x923c,0x1bbed,0x20f7d,0xbc04,0x10522,0x11f3f,0x1db43,0x15379,0x15379,0xa1e7,0xa72,0x0,0x18cec,0x781f,0x539,0x1d60a,0x0,0x214b6,0x272b8,0x172cf,0xd0e8,0x1395c,0x1c65f,0x1d60a,0xffe9,0xc676,0x17d41,0x1685d,0xdb5a,0x12478,0x1b6b4,0x172cf,0xe093,0x23e7e,0x1685d,0x187b3};
        int c = password.charAt(0);
        int counter = 1;
        c = password.charAt(0);     
        counter = 1;   
        while (counter<password.length()){
            int tmp = (c^password.charAt(counter)) *1337;
            if (tmp!=arr[counter-1]) 
                return false;
            c = password.charAt(counter);
            counter++;
        }
        return true;
    }
}