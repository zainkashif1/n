// IN2011 Computer Networks
// Coursework 2023/2024
//
// Submission by
// YOUR_NAME_GOES_HERE
// YOUR_STUDENT_ID_NUMBER_GOES_HERE
// YOUR_EMAIL_GOES_HERE


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

// DO NOT EDIT starts
interface TemporaryNodeInterface {
    public boolean start(String startingNodeName, String startingNodeAddress);
    public boolean store(String key, String value);
    public String get(String key);
}
// DO NOT EDIT ends


public class TemporaryNode implements TemporaryNodeInterface {

    private final Map<String, String> networkMap = new ConcurrentHashMap<>();

    private String hexToBin(String hex) {
        return new BigInteger(hex, 16).toString(2);
    }
    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    private String computeHashIDString(String input) throws NoSuchAlgorithmException {
        byte[] hash = new byte[0]; // Appending newline to comply with your HashID requirements
        try {
            hash = HashID.computeHashID(input + "\n");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return bytesToHex(hash);
    }

    // Method to calculate the distance between two hashIDs as per 2D#4
    private int calculateDistance(String hashID1, String hashID2) {
        String bin1 = hexToBin(hashID1);
        String bin2 = hexToBin(hashID2);

        // Padding to ensure both binary strings are of equal length
        while (bin1.length() < 256) bin1 = "0" + bin1;
        while (bin2.length() < 256) bin2 = "0" + bin2;

        int distance = 256;
        for (int i = 0; i < 256; i++) {
            if (bin1.charAt(i) != bin2.charAt(i)) {
                break;
            }
            distance--;
        }
        return distance;
    }

    private String findNearestNode(String targetHashID) throws NoSuchAlgorithmException {
        String nearestNodeAddress = null;
        int smallestDistance = Integer.MAX_VALUE;

        for (Map.Entry<String, String> entry : networkMap.entrySet()) {
            String nodeName = entry.getKey();
            String nodeAddress = entry.getValue();

            // Assuming you have a method `computeHashID` that can compute the hashID
            // for a node given its name or address. Adjust this to your actual method.
            String nodeHashID = computeHashIDString(nodeName);

            int distance = calculateDistance(targetHashID, nodeHashID);
            if (distance < smallestDistance) {
                smallestDistance = distance;
                nearestNodeAddress = nodeAddress; // Keep the address of the nearest node
            }
        }

        return nearestNodeAddress; // Return the address of the nearest node found
    }

    public boolean start(String startingNodeName, String startingNodeAddress) {
	// Implement this!
	// Return true if the 2D#4 network can be contacted
	// Return false if the 2D#4 network can't be contacted
        String nodeName = "TempNode:" + UUID.randomUUID().toString();
        try {
            String[] addressParts = startingNodeAddress.split(":");
            if (addressParts.length != 2) {
                System.err.println("Invalid starting node address format.");
                return false;
            }
            String address = addressParts[0];
            int port = Integer.parseInt(addressParts[1]);
            networkMap.put(startingNodeName, startingNodeAddress);

            try (Socket socket = new Socket(address, port);
                 OutputStreamWriter outWriter = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

                PrintWriter out = new PrintWriter(outWriter, true);

                // Send START message including the highest protocol version supported and the temporary node's name
                out.println("START 1 " + nodeName);
                out.flush(); // Ensure the message is sent immediately

                // Await and validate the acknowledgment from the starting node
                String response = in.readLine();
                if (response != null && response.startsWith("START")) {
                    // Optionally, you could perform additional actions here, such as updating your node's state or requesting network information
                    // Sending END message for a clean termination of this initial connection setup
                    out.println("END Successful START");
                    out.flush();
                    return true; // Successfully started communication with the network
                } else {
                    System.err.println("Failed to receive valid START acknowledgment.");
                    return false;
                }
            }
        } catch (Exception e) {
            System.err.println("An error occurred while trying to start communication with the network: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public boolean store(String key, String value) {
	// Implement this!
	// Return true if the store worked
	// Return false if the store failed
        try {
            // Append a newline to ensure compliance with the protocol's hashID computation requirements.
            byte[] keyHashBytes = HashID.computeHashID(key + "\n");
            String keyHashID = bytesToHex(keyHashBytes);
            String nearestNode = findNearestNode(keyHashID);
            if (nearestNode == null) {
                System.err.println("No nearest node found for the provided hashID.");
                return false;
            }

            String[] addressParts = nearestNode.split(":");
            if (addressParts.length != 2) {
                System.err.println("Invalid address format of the nearest node.");
                return false;
            }
            String address = addressParts[0];
            int port = Integer.parseInt(addressParts[1]);

            try (Socket socket = new Socket(address, port);
                 OutputStreamWriter outWriter = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

                PrintWriter out = new PrintWriter(outWriter, true);

                // Comply with the protocol: sending START message upon establishing the connection.
                out.println("START 1 " + nearestNode);
                out.flush(); // Immediately flush to ensure timely delivery.

                // Validate START acknowledgment from the server.
                String startAck = in.readLine();
                if (startAck == null || !startAck.startsWith("START")) {
                    System.err.println("Communication failed to start properly with the node.");
                    return false;
                }

                // Format and send the PUT? request as per the 2D#4 protocol.
                // The key and value are each considered as one line for this example.
                out.println("PUT? " + 1 + " " + 1);
                out.println(key + "\n"); // As per the protocol, append '\n'
                out.println(value);
                out.flush(); // Flush to ensure the request is sent immediately.

                // Await and process the response from the nearest node.
                String responseHeader = in.readLine();
                if ("SUCCESS".equals(responseHeader)) {
                    // Optionally, send an END message for clean termination.
                    out.println("END Normal Termination");
                    out.flush();
                    return true; // Indicating the storage was successful.
                } else if ("FAILED".equals(responseHeader)) {
                    // Optionally, send an END message for clean termination.
                    out.println("END Storage Failed");
                    out.flush();
                    return false; // Storage failed at the nearest node.
                }
            }
        } catch (Exception e) {
            System.err.println("An error occurred during the store operation: " + e.getMessage());
            e.printStackTrace();
        }
        return false;
    }

    public String get(String key) {
	// Implement this!
	// Return the string if the get worked
	// Return null if it didn't
        try {
            byte[] keyHashBytes = HashID.computeHashID(key + "\n");
            String keyHashID = bytesToHex(keyHashBytes);
            String nearestNode = findNearestNode(keyHashID);
            if (nearestNode == null) {
                System.err.println("No nearest node found.");
                return null;
            }

            String[] addressParts = nearestNode.split(":");
            if (addressParts.length != 2) {
                System.err.println("Invalid node address format.");
                return null;
            }
            String address = addressParts[0];
            int port = Integer.parseInt(addressParts[1]);

            try (Socket socket = new Socket(address, port);
                 OutputStreamWriter outWriter = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

                // Wrap the OutputStreamWriter in PrintWriter for convenience
                PrintWriter out = new PrintWriter(outWriter, true);

                // Sending START message and flushing
                out.println("START 1 " + nearestNode);
                out.flush(); // Ensure the data is sent immediately

                // Reading acknowledgment
                String startAck = in.readLine();
                if (startAck == null || !startAck.startsWith("START")) {
                    System.err.println("Failed to start communication properly.");
                    return null;
                }

                // Sending GET? request
                out.println("GET? 1");
                out.println(key + "\n"); // Ensure the key ends with a newline
                out.flush(); // Flush to ensure the request is sent

                // Reading and processing the response
                String responseHeader = in.readLine();
                if (responseHeader != null && responseHeader.startsWith("VALUE")) {
                    int valueLines = Integer.parseInt(responseHeader.split(" ")[1]);
                    StringBuilder valueBuilder = new StringBuilder();
                    for (int i = 0; i < valueLines; i++) {
                        valueBuilder.append(in.readLine());
                        if (i < valueLines - 1) {
                            valueBuilder.append("\n");
                        }
                    }
                    return valueBuilder.toString();
                } else if ("NOPE".equals(responseHeader)) {
                    return null;
                }

                // Optionally send an END message if the protocol specifies or if needed for clean termination
                out.println("END Normal Termination");
                out.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // Default return in case of errors or no value found
    }
}
