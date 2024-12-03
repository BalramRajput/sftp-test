package org.example;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.pem.DSSPEMResourceKeyPairParser;
import org.apache.sshd.common.config.keys.loader.pem.ECDSAPEMResourceKeyPairParser;
import org.apache.sshd.common.config.keys.loader.pem.PKCS8PEMResourceKeyPairParser;
import org.apache.sshd.common.config.keys.loader.pem.RSAPEMResourceKeyPairParser;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleKeyPairResourceParser;
import org.apache.sshd.common.util.security.eddsa.Ed25519PEMResourceKeyParser;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class Main {
    private static final String username = "username";
    private static final String privateKey = "private Key as string";
    private static final String password = "user's password";
    private static final String passphrase = "private key passphrase";
    private static final String host = "host";
    private static final int port = 22;

    private static final String DIR = "/";
    private static final String PVTKEY = "privatekey";
    // Different parsers to handle different keys
    private static final List<KeyPairResourceLoader> KEY_PAIR_RESOURCE_LOADERS = Arrays.asList(
            RSAPEMResourceKeyPairParser.INSTANCE,
            OpenSSHKeyPairResourceParser.INSTANCE,
            DSSPEMResourceKeyPairParser.INSTANCE,
            ECDSAPEMResourceKeyPairParser.INSTANCE,
            Ed25519PEMResourceKeyParser.INSTANCE,
            PKCS8PEMResourceKeyPairParser.INSTANCE,
            BouncyCastleKeyPairResourceParser.INSTANCE
    );

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        System.out.println(new Main().verifyConnection(host, port));
    }

    public boolean verifyConnection(String host, int port) {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();
            return establishSessionAndCheckPermissions(client, host, port);
        } catch (IOException e) {
            System.err.println("Failed to start SFTP client: " +  e.getMessage());
            throw new RuntimeException("Failed to connect to the SFTP server. Error: " + e.getMessage());
        }
    }

    private boolean establishSessionAndCheckPermissions(SshClient client, String host, int port) {

        try (ClientSession session = createSession(client, host, port)) {
            authenticateSession(session);
            return checkUserPermissions(session);
        } catch (Exception e) {
            System.err.println("Error occurred while verifying connection: " + e.getMessage());
            throw new RuntimeException("Connection verification failed", e);
        }
    }

    private ClientSession createSession(SshClient client, String host, int port) throws IOException {
        System.out.println("Connecting to SSH server at " + host + ":" + port);
        ClientSession session = client.connect(username, host, port)
                .verify(10000)
                .getSession();
        System.out.println("Successfully connected to SSH server.");
        return session;
    }

    private void authenticateSession(ClientSession session) {
        try {
            if (privateKey != null && !privateKey.isEmpty()) {
                authenticateWithPrivateKey(session, privateKey, passphrase);
            }
            if (password != null && !password.isEmpty()) {
                session.addPasswordIdentity(password);
            }
            session.auth().verify(10000);
            System.out.println("Authentication successful.");
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Authentication failed: " + e.getMessage());
            throw new RuntimeException("Authentication failed", e);
        }
    }

    private void authenticateWithPrivateKey(ClientSession session, String privateKey, String passphrase) throws IOException, GeneralSecurityException {
        System.out.println("Authenticating using private key.");
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(privateKey.getBytes(StandardCharsets.UTF_8))) {
            IoResource<String> resource = createPrivateKeyResource(privateKey, inputStream);
            Collection<KeyPair> keys = getKeyPairs(session, resource, getPassphraseProvider(passphrase));
            session.addPublicKeyIdentity(keys.iterator().next());
        }
    }

    private Collection<KeyPair> getKeyPairs(ClientSession session, IoResource<String> resource, FilePasswordProvider passphraseProvider) throws GeneralSecurityException, IOException {
        for(KeyPairResourceLoader keyPairResourceLoader: KEY_PAIR_RESOURCE_LOADERS){
            Collection<KeyPair> keyPairs = keyPairResourceLoader.loadKeyPairs(session, resource, passphraseProvider);
            if(keyPairs != null && !keyPairs.isEmpty()){
                return keyPairs;
            }
        }
        throw new RuntimeException("Provided private key is not supported!");
    }

    private IoResource<String> createPrivateKeyResource(String privateKey, ByteArrayInputStream inputStream) {
        return new IoResource<>() {
            @Override
            public Class<String> getResourceType() {
                return String.class;
            }

            @Override
            public String getResourceValue() {
                return privateKey;
            }

            @Override
            public String getName() {
                return PVTKEY;
            }

            @Override
            public InputStream openInputStream() throws IOException {
                return inputStream;
            }
        };
    }

    private FilePasswordProvider getPassphraseProvider(String passphrase) {
        return (passphrase != null && !passphrase.isEmpty()) ? FilePasswordProvider.EMPTY : FilePasswordProvider.of(passphrase);
    }

    private boolean checkUserPermissions(ClientSession session) {
        try (SftpClient sftpClient = SftpClientFactory.instance().createSftpClient(session)) {
            SftpClient.Attributes stat = sftpClient.stat(DIR);
            int permissions = stat.getPermissions();

            if ((permissions & 00400) != 0) {
                System.out.println("User has permission to access the directory.");
                System.out.println("Content: ");
                Iterable<SftpClient.DirEntry> dirEntries = sftpClient.readDir(DIR);
                for(SftpClient.DirEntry dir: dirEntries){
                    System.out.println(dir.getFilename());
                }
                return true;
            } else {
                System.err.println("User does not have permission to access the directory.");
                return false;
            }
        } catch (IOException e) {
            System.err.println("Failed to retrieve permissions for directory: " + e.getMessage());
            throw new RuntimeException("Failed to check permissions", e);
        }
    }

}