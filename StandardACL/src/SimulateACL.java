import java.io.BufferedReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SimulateACL {

	public Map<Integer, ArrayList<String>> MAP_ACL_STATEMENT = new HashMap<Integer, ArrayList<String>>();
	public ArrayList<String> IP_LIST = new ArrayList<String>();

	public Map<Integer, ArrayList<String>> loadACL(BufferedReader aclReaderStream) {

		ArrayList<String> ACL_STATMENT_INFO = new ArrayList<String>();

//		String interfaceNumber = "";

		int countACLStatments = -1;

		int checkerCounter = 0;
		int exitCounter = 0;
		try {
			// Reading first line to get accesslist statment
			while (aclReaderStream != null) {

				String firstLine = aclReaderStream.readLine();

				// Security to check null values at the end of the file
				if (checkerCounter != 0) {
					exitCounter++;
					if (exitCounter > 2) {
						break;
					}
				}
				checkerCounter++;

				// Check for empty line at beginning
				if (firstLine != null && !firstLine.isEmpty()) {

					// Split first line to get info on acl
					String[] accessListInfo = firstLine.split(" ");

					// Store aclNumber, sourceIP and mask
					if (accessListInfo[0].toLowerCase().equalsIgnoreCase("access-list")) {
						ACL_STATMENT_INFO.add(accessListInfo[1]);
						ACL_STATMENT_INFO.add(accessListInfo[2]);
						ACL_STATMENT_INFO.add(accessListInfo[3]);
						ACL_STATMENT_INFO.add(accessListInfo[4]);
						countACLStatments++;
						MAP_ACL_STATEMENT.put(countACLStatments, ACL_STATMENT_INFO);

					} else if (accessListInfo[0].toLowerCase().equalsIgnoreCase("interface")) {
//						interfaceNumber = accessListInfo[1];
					} else if (accessListInfo[0].toLowerCase().equalsIgnoreCase("ip")) {

						for (int i : MAP_ACL_STATEMENT.keySet()) {
							if (MAP_ACL_STATEMENT.containsKey(i)) {
								if (!MAP_ACL_STATEMENT.get(i).get(0).equals(accessListInfo[2].toLowerCase())) {
									System.out.println("ERROR: INCORRECT ACL !!");
								}
							}
						}
					}

					checkerCounter = 0;
				}
				ACL_STATMENT_INFO = new ArrayList<String>();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return MAP_ACL_STATEMENT;
	}

	public ArrayList<String> loadIPFile(BufferedReader IPAddressFilePath) {

		int checkerCounter = 0;
		int exitCounter = 0;
		while (IPAddressFilePath != null) {

			try {

				// Security to check null values at the end of the file
				if (checkerCounter != 0) {
					exitCounter++;
					if (exitCounter > 2) {
						break;
					}
				}

				checkerCounter++;

				// Reading first line to get accesslist statment
				String firstLine = IPAddressFilePath.readLine();

				// Check for empty line at beginning
				if (firstLine != null && !firstLine.isEmpty()) {
					IP_LIST.add(firstLine);
					checkerCounter = 0;

				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return IP_LIST;
	}

	public void checkIncomingNetwork(Map<Integer, ArrayList<String>> mapOfACLCommandList, ArrayList<String> listOfIPs) {

		ArrayList<String> deniedIPs = new ArrayList<String>();
		ArrayList<String> permittedIPs = new ArrayList<String>();
		boolean[] byteWiseFlag = { false, false, false, false };
		boolean[] idealFlag = { true, true, true, true };
		boolean[] resetFlag = { false, false, false, false };

		for (String incomingIP : listOfIPs) {
			String[] tempSorceIP = incomingIP.split("\\.");

			for (Integer aclCount : mapOfACLCommandList.keySet()) {

				if (mapOfACLCommandList.get(aclCount).get(1).equalsIgnoreCase("deny")) {

					String[] tempDeniedIPNetwork = mapOfACLCommandList.get(aclCount).get(2).split("\\.");
					String[] tempDeniedIPNetworkMask = mapOfACLCommandList.get(aclCount).get(3).split("\\.");

					for (int i = 0; i < tempDeniedIPNetworkMask.length; i++) {
						if (tempDeniedIPNetworkMask[i].equalsIgnoreCase("0")) {
							if (tempSorceIP[i].equalsIgnoreCase(tempDeniedIPNetwork[i])) {
								byteWiseFlag[i] = true;
							} else {
								break;
							}
						} else if (tempDeniedIPNetworkMask[i].equalsIgnoreCase("255")) {
							byteWiseFlag[i] = true;
						}
					}

					if (Arrays.equals(byteWiseFlag, idealFlag)) {
						deniedIPs.add(incomingIP);
						byteWiseFlag = resetFlag;

						System.out.println("Packet from " + incomingIP + " denied");
						resetFlag = new boolean[4];
					}
				}

				else if (mapOfACLCommandList.get(aclCount).get(1).equalsIgnoreCase("permit")) {

					String[] tempDeniedIPNetwork = mapOfACLCommandList.get(aclCount).get(2).split("\\.");
					String[] tempDeniedIPNetworkMask = mapOfACLCommandList.get(aclCount).get(3).split("\\.");

					for (int i = 0; i < tempDeniedIPNetworkMask.length; i++) {
						if (tempDeniedIPNetworkMask[i].equalsIgnoreCase("0")) {
							if (tempSorceIP[i].equalsIgnoreCase(tempDeniedIPNetwork[i])) {
								byteWiseFlag[i] = true;
							} else {
								break;
							}
						} else if (tempDeniedIPNetworkMask[i].equalsIgnoreCase("255")) {
							byteWiseFlag[i] = true;
						}
					}

					if (!deniedIPs.contains(incomingIP)) {
						if (Arrays.equals(byteWiseFlag, idealFlag)) {
							permittedIPs.add(incomingIP);
							byteWiseFlag = resetFlag;
							resetFlag = new boolean[4];

							System.out.println("Packet from " + incomingIP + " permitted");

						} else {
							deniedIPs.add(incomingIP);
							System.out.println("Packet from " + incomingIP + " denied");

							byteWiseFlag = resetFlag;
							resetFlag = new boolean[4];
						}
					} else {
						byteWiseFlag = resetFlag;
						resetFlag = new boolean[4];
					}
				}
			}
		}
	}
}
