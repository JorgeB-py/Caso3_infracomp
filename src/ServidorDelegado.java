import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServidorDelegado extends Thread {
    private static final String PRIVATE_KEY_FILE = "privateKey.ser";
    private static final String PUBLIC_KEY_FILE = "publicKey.ser";
    private ArrayList<Integer> idCliente;
    private HashMap<Integer, Estados> paquetes;
    private Socket socket;

    public ServidorDelegado(ArrayList<Integer> idCliente, HashMap<Integer, Estados> paquetes, Socket socket) {
        this.idCliente = idCliente;
        this.paquetes = paquetes;
        this.socket = socket;
    }

    public void run() {

        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
            privateKey = (PrivateKey) ois.readObject();
            System.out.println("Llave privada leída exitosamente.");
            ObjectInputStream ois2 = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
            publicKey = (PublicKey) ois2.readObject();
            System.out.println("Llave pública leída exitosamente.");

            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);

            System.out.println(lector.readLine());

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            String receivedMessage = lector.readLine();
            byte[] decodedMessage = Base64.getDecoder().decode(receivedMessage);
            byte[] mensajeBytes = cipher.doFinal(decodedMessage);
            String mensajeDesencriptado = new String(mensajeBytes);
            System.out.println("Mensaje recibido: " + mensajeDesencriptado);
            escritor.println(mensajeDesencriptado);

            if(lector.readLine().equals("OK")){
                System.out.println("Cliente autenticado");
            }else{
                System.out.println("Error en la autenticación");
                ois.close();
                ois2.close();
                throw new Exception("Error en la autenticación");
            }
            ProcessBuilder processBuilder = new ProcessBuilder("C:\\Users\\jorgi\\Desktop\\Uniandes\\infracomp\\Caso3_infracomp\\lib\\OpenSSL-1.1.1h_win32\\openssl.exe", "dhparam", "-text", "1024");
            Process process = processBuilder.start();
            // Leer la salida del commando
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder hexPrime = new StringBuilder();
            BigInteger primeNumber = null;
            int generatorNumber=0;

            boolean readingPrime = false;
            while ((line = reader.readLine()) != null) {
                if (line.contains("prime:")) {
                    // Comienza a leer el número primo
                    readingPrime = true;
                } else if (line.contains("generator:")) {
                    // Fin del número primo, inicio del generador
                    readingPrime = false;
                    String[] parts = line.split(" ");
                    generatorNumber = Integer.parseInt(parts[9]); // Generador en decimal
                } else if (readingPrime) {
                    // Extraer el valor en hexadecimal
                    hexPrime.append(line.trim().replace(":", ""));
                }
            }

            // Convertir el número primo en hexadecimal a BigInteger
            primeNumber = new BigInteger(hexPrime.toString(), 16);
            long x = Math.round(Math.random());

            int generatorNumberX = (int) Math.pow(generatorNumber, x);

            escritor.println(generatorNumber);
            escritor.println(primeNumber.toString());
            escritor.println(generatorNumberX);
            
            BigInteger firmar = BigInteger.valueOf(generatorNumber)
                .add(BigInteger.valueOf(generatorNumberX))
                .add(primeNumber);

            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);

            byte[] datos_firma = firmar.toByteArray();
            signature.update(datos_firma);

            byte[] firmaBytes = signature.sign();
            String firmaBase64 = Base64.getEncoder().encodeToString(firmaBytes);

            // Enviar la firma en Base64
            escritor.println(firmaBase64);

            if (lector.readLine().equals("OK")) {
                System.out.println("Firma correcta");
            } else {
                System.out.println("Firma no correcta");
            }

            int Y= Integer.parseInt(lector.readLine());

            int generatorNumberXY= (int)Math.pow(generatorNumberX, Y);

            BigInteger masterkey = BigInteger.valueOf(generatorNumberXY).mod(primeNumber);

            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);

            escritor.println(ivBytes);

            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

            byte[] hash = sha512.digest(masterkey.toByteArray());

            byte[] key1 = new byte[32];
            byte[] key2 = new byte[32];

            System.arraycopy(hash, 0, key1, 0, 32);
            System.arraycopy(hash, 32, key2, 0, 32);

            SecretKey K_AB1 = new SecretKeySpec(key1, "AES");
            SecretKey K_AB2 = new SecretKeySpec(key2, "HmacSHA256");

            int uid = Integer.parseInt(lector.readLine());
            String hmac_uid = lector.readLine();

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(K_AB2);
            byte[] computedHmacUid = mac.doFinal(Integer.toString(uid).getBytes());
            String computedHmacUidBase64 = Base64.getEncoder().encodeToString(computedHmacUid);

            if (!computedHmacUidBase64.equals(hmac_uid)) {
                escritor.println("HMAC del UID no coincide");
                return;
            }

            String paquete_id = lector.readLine();
            String hmac_paquete = lector.readLine();

            int paqueteIdDecoded = Integer.parseInt(new String(Base64.getDecoder().decode(paquete_id)));
            mac.init(K_AB2);
            byte[] computedHmacPaquete = mac.doFinal(Integer.toString(paqueteIdDecoded).getBytes());
            String computedHmacPaqueteBase64 = Base64.getEncoder().encodeToString(computedHmacPaquete);

            if (!computedHmacPaqueteBase64.equals(hmac_paquete)) {
                escritor.println("HMAC del paquete no coincide");
                return;
            }

            System.out.println("hmacs validas");







            reader.close();
            process.waitFor();

            // Enviar respuesta
            socket.close();
            ois.close();
            ois2.close();
            escritor.close();
            lector.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}
