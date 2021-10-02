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
			SimulateExtendedACL objACL = new SimulateExtendedACL();

			Map<Integer, ArrayList<String>> tempACLCommands = objACL.loadACL(aclReader);
			Map<Integer, ArrayList<String>> mapIPsAndPorts = objACL.loadIPFile(ipReader);

			objACL.checkIncomingNetwork(tempACLCommands, mapIPsAndPorts);

		} catch (Exception e) {
			e.printStackTrace();
		}
		sc.close();
	}
}