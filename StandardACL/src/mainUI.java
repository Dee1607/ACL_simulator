import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Map;
import java.util.Scanner;

public class mainUI {
	public static void main(String args[]) {
		Scanner sc = new Scanner(System.in);
		String ACLFilePath = "";
		String IPAddressFilePath = "";

		System.out.println("Enter Access Control List(ACL) File Path: ");
		ACLFilePath = sc.next();

		System.out.println("Enter IP Address Containing File Path: ");
		IPAddressFilePath = sc.next();

		BufferedReader aclReader = null;
		BufferedReader ipReader = null;

		try {
			aclReader = new BufferedReader(new FileReader(ACLFilePath));
			ipReader = new BufferedReader(new FileReader(IPAddressFilePath));
			SimulateACL objACL = new SimulateACL();

			Map<Integer, ArrayList<String>> tempACLCommands = objACL.loadACL(aclReader);
			ArrayList<String> tempIPList = objACL.loadIPFile(ipReader);

			objACL.checkIncomingNetwork(tempACLCommands, tempIPList);

		} catch (Exception e) {
			e.printStackTrace();
		}
		sc.close();
	}
}
