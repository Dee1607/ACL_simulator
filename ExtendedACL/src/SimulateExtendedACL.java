import java.io.BufferedReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SimulateExtendedACL {

	public Map<Integer, ArrayList<String>> MAP_ACL_STATEMENT = new HashMap<Integer, ArrayList<String>>();
	public ArrayList<String> IP_LIST = new ArrayList<String>();

	public Map<Integer, ArrayList<String>> loadACL(BufferedReader aclReaderStream) {

		ArrayList<String> ACL_STATMENT_INFO = new ArrayList<String>();

		// Just in case of Future Use
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

						for (String str : accessListInfo) {

							ACL_STATMENT_INFO.add(str);
						}

						countACLStatments++;
						MAP_ACL_STATEMENT.put(countACLStatments, ACL_STATMENT_INFO);

					} else if (accessListInfo[0].toLowerCase().equalsIgnoreCase("interface")) {
//						interfaceNumber = accessListInfo[1];
					} else if (accessListInfo[0].toLowerCase().equalsIgnoreCase("ip")) {

						for (int i : MAP_ACL_STATEMENT.keySet()) {
							if (MAP_ACL_STATEMENT.containsKey(i)) {
								if (!MAP_ACL_STATEMENT.get(i).get(1).equals(accessListInfo[2].toLowerCase())) {
									System.out.println("ERROR: INCORRECT ACL (Two different interface detected) !!");
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

	public Map<Integer, ArrayList<String>> loadIPFile(BufferedReader IPAddressFilePath) {

		// 1. Source IP
		// 2. Destination IP
		// 3. Port range or port number
		Map<Integer, ArrayList<String>> mapIPsAndPorts = new HashMap<Integer, ArrayList<String>>();

		ArrayList<String> listSourceIP = new ArrayList<String>();
		ArrayList<String> listDestinationIp = new ArrayList<String>();
		ArrayList<String> listPortNumbers = new ArrayList<String>();

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

					String[] tempSplit = firstLine.split(" ");
					listSourceIP.add(tempSplit[0]);
					listDestinationIp.add(tempSplit[1]);
					listPortNumbers.add(tempSplit[2]);
					checkerCounter = 0;
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		mapIPsAndPorts.put(1, listSourceIP);
		mapIPsAndPorts.put(2, listDestinationIp);
		mapIPsAndPorts.put(3, listPortNumbers);

		return mapIPsAndPorts;
	}

	public void checkIncomingNetwork(Map<Integer, ArrayList<String>> mapOfACLCommandList,
			Map<Integer, ArrayList<String>> tempMapIPsAndPorts) {

		ArrayList<String> deniedSourceIPs = new ArrayList<String>();
		ArrayList<String> deniedDestinationIPs = new ArrayList<String>();
		ArrayList<Integer> deniedPortNumbers = new ArrayList<Integer>();

		ArrayList<String> permittedSourceIPs = new ArrayList<String>();
		ArrayList<String> permittedDestinationIPs = new ArrayList<String>();
		ArrayList<Integer> permittedPortNumbers = new ArrayList<Integer>();

		boolean[] byteSourceIPFlag = { false, false, false, false };
		boolean[] byteDestinationIPFlag = { false, false, false, false };
		boolean portFlag = false;

		boolean[] idealFlag = { true, true, true, true };
		boolean[] resetFlag = { false, false, false, false };

		ArrayList<String> listOfSourceIPs = tempMapIPsAndPorts.get(1);
		ArrayList<String> listOfDestinationIPs = tempMapIPsAndPorts.get(2);
		ArrayList<String> listOfPorts = tempMapIPsAndPorts.get(3);

		for (int j = 0; j < listOfSourceIPs.size(); j++) {

			String[] byteWiseSourceIPToCheck = listOfSourceIPs.get(j).split("\\.");
			String[] byteWiseDestinationIPToCheck = listOfDestinationIPs.get(j).split("\\.");
			String incomingPortNumber = listOfPorts.get(j);

			for (Integer aclCount : mapOfACLCommandList.keySet()) {

				if (mapOfACLCommandList.get(aclCount).get(2).equalsIgnoreCase("deny")) {

					String[] tempDeniedSourceIPNetwork = mapOfACLCommandList.get(aclCount).get(4).split("\\.");
					String[] tempDeniedSourceIPNetworkMask = mapOfACLCommandList.get(aclCount).get(5).split("\\.");

					// Checking Source IP
					for (int i = 0; i < tempDeniedSourceIPNetworkMask.length; i++) {
						if (tempDeniedSourceIPNetworkMask[i].equalsIgnoreCase("0")) {
							if (byteWiseSourceIPToCheck[i].equalsIgnoreCase(tempDeniedSourceIPNetwork[i])) {
								byteSourceIPFlag[i] = true;
							} else {
								break;
							}
						} else if (tempDeniedSourceIPNetworkMask[i].equalsIgnoreCase("255")) {
							byteSourceIPFlag[i] = true;
						}
					}

					if (Arrays.equals(byteSourceIPFlag, idealFlag)) {

						byteSourceIPFlag = resetFlag;
						resetFlag = new boolean[4];

						String[] tempDeniedDestinationIPNetwork = mapOfACLCommandList.get(aclCount).get(6).split("\\.");
						String[] tempDeniedDestinationIPNetworkMask = mapOfACLCommandList.get(aclCount).get(7)
								.split("\\.");

						// Checking Destination IP
						for (int i = 0; i < tempDeniedDestinationIPNetworkMask.length; i++) {
							if (tempDeniedDestinationIPNetworkMask[i].equalsIgnoreCase("0")) {
								if (byteWiseDestinationIPToCheck[i]
										.equalsIgnoreCase(tempDeniedDestinationIPNetwork[i])) {
									byteDestinationIPFlag[i] = true;
								} else {
									break;
								}
							} else if (tempDeniedDestinationIPNetworkMask[i].equalsIgnoreCase("255")) {
								byteDestinationIPFlag[i] = true;
							}
						}

						if (Arrays.equals(byteDestinationIPFlag, idealFlag)) {

							byteDestinationIPFlag = resetFlag;
							resetFlag = new boolean[4];

							if (mapOfACLCommandList.get(aclCount).get(8).equalsIgnoreCase("range")) {
								String[] portNumbers = mapOfACLCommandList.get(aclCount).get(9).split("-");

								for (int start = Integer.parseInt(portNumbers[0]); start <= Integer
										.parseInt(portNumbers[1]); start++) {
									deniedPortNumbers.add(start);
									if (Integer.parseInt(incomingPortNumber) == start) {
										portFlag = true;
									}
								}

							} else if (mapOfACLCommandList.get(aclCount).get(8).equalsIgnoreCase("eq")) {
								if (Integer.parseInt(incomingPortNumber) == Integer
										.parseInt(mapOfACLCommandList.get(aclCount).get(9))) {
									portFlag = true;
								}
							}

							if (portFlag) {
								deniedSourceIPs.add(listOfSourceIPs.get(j));
								deniedDestinationIPs.add(listOfDestinationIPs.get(j));

								System.out.println("Packet from " + listOfSourceIPs.get(j) + " to "
										+ listOfDestinationIPs.get(j) + " on port " + incomingPortNumber + " denied.");

								// Add port numbers to list
								// deniedPorts.add(e);
								byteSourceIPFlag = resetFlag;
								resetFlag = new boolean[4];
								byteDestinationIPFlag = resetFlag;
								resetFlag = new boolean[4];
								portFlag = false;
							}
						}
					}
				}

				else if (mapOfACLCommandList.get(aclCount).get(2).equalsIgnoreCase("permit")) {
					String[] tempPermittedSourceIPNetwork = mapOfACLCommandList.get(aclCount).get(4).split("\\.");
					String[] tempPermittedSourceIPNetworkMask = mapOfACLCommandList.get(aclCount).get(5).split("\\.");

					byteSourceIPFlag = resetFlag;
					resetFlag = new boolean[4];
					byteDestinationIPFlag = resetFlag;
					resetFlag = new boolean[4];

					for (int i = 0; i < tempPermittedSourceIPNetworkMask.length; i++) {
						if (tempPermittedSourceIPNetworkMask[i].equalsIgnoreCase("0")) {
							if (byteWiseSourceIPToCheck[i].equalsIgnoreCase(tempPermittedSourceIPNetwork[i])) {
								byteSourceIPFlag[i] = true;
							} else {
								break;
							}
						} else if (tempPermittedSourceIPNetworkMask[i].equalsIgnoreCase("255")) {
							byteSourceIPFlag[i] = true;
						}
					}

					if (Arrays.equals(byteSourceIPFlag, idealFlag)) {
						permittedSourceIPs.add(listOfSourceIPs.get(j));
						byteSourceIPFlag = resetFlag;
						resetFlag = new boolean[4];

						// Check DEstination IPs
						String[] tempPermittedDestinationIPNetwork = mapOfACLCommandList.get(aclCount).get(6)
								.split("\\.");
						String[] tempPermittedDestinationIPNetworkMask = mapOfACLCommandList.get(aclCount).get(7)
								.split("\\.");

						for (int i = 0; i < tempPermittedDestinationIPNetworkMask.length; i++) {
							if (tempPermittedDestinationIPNetworkMask[i].equalsIgnoreCase("0")) {
								if (byteWiseDestinationIPToCheck[i]
										.equalsIgnoreCase(tempPermittedDestinationIPNetwork[i])) {
									byteDestinationIPFlag[i] = true;
								} else {
									break;
								}
							} else if (tempPermittedDestinationIPNetworkMask[i].equalsIgnoreCase("255")) {
								byteDestinationIPFlag[i] = true;
							}

							if (Arrays.equals(byteDestinationIPFlag, idealFlag)) {

								byteDestinationIPFlag = resetFlag;
								resetFlag = new boolean[4];

								if (mapOfACLCommandList.size() > 8) {
									if (mapOfACLCommandList.get(aclCount).get(8).equalsIgnoreCase("range")) {
										String[] portNumbers = mapOfACLCommandList.get(aclCount).get(9).split("-");

										for (int start = Integer.parseInt(portNumbers[0]); start <= Integer
												.parseInt(portNumbers[1]); start++) {
											permittedPortNumbers.add(start);
											if (Integer.parseInt(incomingPortNumber) == start) {
												portFlag = true;
											}
										}

									} else if (mapOfACLCommandList.get(aclCount).get(8).equalsIgnoreCase("eq")) {
										if (Integer.parseInt(incomingPortNumber) == Integer
												.parseInt(mapOfACLCommandList.get(aclCount).get(9))) {
											portFlag = true;
										}
									}
								} else {
									portFlag = true;
								}

								if (portFlag) {
									permittedSourceIPs.add(listOfSourceIPs.get(j));
									permittedDestinationIPs.add(listOfSourceIPs.get(j));

									byteSourceIPFlag = resetFlag;
									resetFlag = new boolean[4];
									byteDestinationIPFlag = resetFlag;
									resetFlag = new boolean[4];

									portFlag = false;

									System.out.println("Packet from " + listOfSourceIPs.get(j) + " to "
											+ listOfDestinationIPs.get(j) + " on port " + incomingPortNumber
											+ " permitted.");
								}
							}
						}
					}
				}
			}
		}
	}
}