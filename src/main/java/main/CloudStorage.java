package main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.List;

import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.blob.CloudBlob;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import com.microsoft.azure.storage.blob.ListBlobItem;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CloudStorage {

	private static final String HELP = "help";

	private static final String REMOVE = "remove";

	private static final String LIST = "list";

	private static final String GENERATE_KEY = "generate-key";

	public static final String TEMP_FILE_PATH = "temp-cipher.txt";

	private static final String DECRYPT = "decrypt";

	private static final String ENCRYPT = "encrypt";

	public static final String CONNECTION = "DefaultEndpointsProtocol=http;"
			+ "AccountName=ait1;"
			+ "AccountKey=UzbdlqbrAIls5IJB1PpJLj1COmw28CP6Pcb7Wlm9JNY+Oo/fgWmwEBMKToX+85r5Rf6pBYKcf2TR9cf+nVieLw==";

	private static final String HELP_TEXT = "Available commands:\n"
			+ "add source_path name -- add the specified file to the cloud as \"name\"\n"
			+ "download name destination_path -- download the specified file from the cloud and save it at destination_path"
			+ "remove name -- remove the specified file from the cloud\n"
			+ "list -- list all the files currently uploaded";

	private static final String UPLOAD = "upload";

	private static final String DOWNLOAD = "download";

	private CloudStorageAccount storageAccount;
	private CloudBlobContainer container;

	private EncryptionModule encMod;

	private BufferedReader in;

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
		in = new BufferedReader(new InputStreamReader(System.in));
		encMod = new EncryptionModule(in);

		String command = in.readLine();
		while (!command.equals("exit")) {
			if (command.startsWith(UPLOAD)) {
				String args = command.substring(UPLOAD.length() + 1);
				String sourceFilePath = args.substring(0, args.indexOf(' '));
				String destName = args.substring(args.indexOf(' ') + 1);
				try {
					CloudBlockBlob blob = container
							.getBlockBlobReference(destName);
					encMod.encrypt(sourceFilePath);
					blob.upload(new FileInputStream(TEMP_FILE_PATH), new File(
							TEMP_FILE_PATH).length());
				} catch (Exception e) {
					e.printStackTrace();
				}
				System.out.println("File uploaded to cloud as " + destName);
			} else if (command.startsWith(DOWNLOAD)) {
				String args = command.substring(DOWNLOAD.length() + 1);
				String itemName = args.substring(0, args.indexOf(' '));
				String destinationFilePath = args
						.substring(args.indexOf(' ') + 1);
				try {
					CloudBlob blob = container.getBlockBlobReference(itemName);
					blob.download(new FileOutputStream(TEMP_FILE_PATH));
					encMod.decrypt(TEMP_FILE_PATH, destinationFilePath);
				} catch (URISyntaxException | StorageException e) {
					e.printStackTrace();
				}
			} else if (command.startsWith(LIST)) {
				// list the files uploaded to the default blob/container
				for (ListBlobItem blobItem : container.listBlobs()) {
					System.out.println(blobItem.getUri());
				}
			} else if (command.startsWith(REMOVE)) {
				// delete the specified file from the blob/container
				String itemName = command.substring(REMOVE.length() + 1);
				try {
					CloudBlob blob = container.getBlockBlobReference(itemName);
					blob.delete();
				} catch (URISyntaxException | StorageException e) {
					e.printStackTrace();
				}
			} else if (command.startsWith(HELP)) {
				System.out.println(HELP_TEXT);
			} else if (command.startsWith(ENCRYPT)) {
				String args = command.substring(ENCRYPT.length() + 1);
				String source = args.substring(0, args.indexOf(' '));
				String destination = args.substring(args.indexOf(' ') + 1);
				encMod.encrypt(source, destination);
			} else if (command.startsWith(DECRYPT)) {
				String args = command.substring(ENCRYPT.length() + 1);
				String source = args.substring(0, args.indexOf(' '));
				String destination = args.substring(args.indexOf(' ') + 1);
				encMod.decrypt(source, destination);
			} else if (command.startsWith(GENERATE_KEY)) {
				encMod.generateAndSaveKey();
			} else {
				System.out.println("Unsupported command!");
			}

			command = in.readLine();
		}
	}

}
