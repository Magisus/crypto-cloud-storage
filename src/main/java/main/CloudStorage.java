package main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.Security;

import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CloudStorage {

	public static final String CONNECTION = "DefaultEndpointsProtocol=http;"
			+ "AccountName=ait1;"
			+ "AccountKey=UzbdlqbrAIls5IJB1PpJLj1COmw28CP6Pcb7Wlm9JNY+Oo/fgWmwEBMKToX+85r5Rf6pBYKcf2TR9cf+nVieLw==";

	private static final String HELP_TEXT = "Available commands:\n"
			+ "add source_path name -- add the specified file to the cloud as \"name\"\n"
			+ "download name destination_path -- download the specified file from the cloud and save it at destination_path"
			+ "remove name -- remove the specified file from the cloud\n"
			+ "list -- list all the files currently uploaded";

	private static final String ADD = "add";

	private CloudStorageAccount storageAccount;
	private CloudBlobContainer container;

	public static void main(String[] args) {

		Security.addProvider(new BouncyCastleProvider());

		try {
			new CloudStorage().processCommands();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public CloudStorage() throws InvalidKeyException, URISyntaxException,
			StorageException {
		// Retrieve storage account from connection-string.
		storageAccount = CloudStorageAccount.parse(CONNECTION);

		// Create the blob client.
		CloudBlobClient blobClient = storageAccount.createCloudBlobClient();

		// Get a reference to a container.
		// The container name must be lower case
		container = blobClient.getContainerReference("mycontainer");

		// Create the container if it does not exist.
		container.createIfNotExists();
	}

	private void processCommands() throws IOException {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

		String command = in.readLine();
		while (command != "exit") {
			if (command.startsWith(ADD)) {
				String args = command.substring(ADD.length() + 1);
				String filePath = args.substring(0, args.indexOf(' '));
				String destName = args.substring(args.indexOf(' '));
				try {
					CloudBlockBlob blob = container
							.getBlockBlobReference(destName);
					File source = new File(filePath);
					blob.upload(new FileInputStream(source), source.length());
				} catch (Exception e) {
					e.printStackTrace();
				}
				System.out.println("File uploaded to cloud as " + destName);
			} else if (command.startsWith("list")) {
				// list the files uploaded to the default blob/container
			} else if (command.startsWith("remove")) {
				// delete the specified file from the blob/container
			} else if (command.startsWith("help")) {
				System.out.println(HELP_TEXT);
			} else if (command.startsWith("encrypt-test")) {
				EncryptionModule enc = new EncryptionModule();
				String cipherText = enc.encrypt();
				enc.decrypt(cipherText);
			} else {
				System.out.println("Unsupported command!");
			}

			command = in.readLine();
		}
	}

}
