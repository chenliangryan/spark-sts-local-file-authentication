package guru.darc.spark.sts;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hive.service.auth.PasswdAuthenticationProvider;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;
import javax.security.sasl.AuthenticationException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class LocalFileAuthentication implements PasswdAuthenticationProvider
{
    private final Map<String, String> userMap;

    public LocalFileAuthentication()
    {
        userMap = new HashMap<>();
        HiveConf conf = new HiveConf();
        String stsUserFilePath = conf.get("hive.server2.custom.authentication.stsUserFile");
        loadUsersFromFile(stsUserFilePath);
    }

    @Override
    public void Authenticate(String username, String password)
            throws AuthenticationException  {
        String storedPassword = userMap.get(username);
        if (storedPassword == null) {
            throw new AuthenticationException("User " + username + " not found");
        }

        String hashedPassword = hashPasswordSHA1(password);
        if (! storedPassword.equals(hashedPassword)) {
            throw new AuthenticationException("Wrong password for user " + username);
        }
    }

    private void loadUsersFromFile(String userFile) {
        if (userFile == null) {
            throw new RuntimeException("Unable to find STS user file");
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(userFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    userMap.put(parts[0], parts[1]);
                } else {
                    System.err.println("Invalid user line: " + line);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error reading user file: " + e.getMessage(), e);
        }
    }

    private static String hashPasswordSHA1(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashedBytes = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 algorithm not available", e);
        }
    }
}