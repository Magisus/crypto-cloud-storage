package main;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CloudStorage {

	private static final String HELP_TEXT = "Available commands:\n"
			+ "add filename -- add the specified file to the cloud\n"
			+ "remove filename -- remove the specified file from the cloud\n"
			+ "list -- list all the files currently uploaded";

	public static void main(String[] args) {

		new CloudStorage().processCommands();

	}

	private void processCommands() {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

		String command = "";
		try {
			command = in.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		while (command != "exit") {
			if (command.startsWith("add")) {
				// add the specified file to the default blob/container
			} else if (command.startsWith("list")) {
				// list the files uploaded to the default blob/container
			} else if (command.startsWith("remove")) {
				// delete the specified file from the blob/container
			} else if (command.startsWith("help")) {
				System.out.println(HELP_TEXT);
			} else {
				System.out.println("Unsupported command!");
			}
		}
	}

}
