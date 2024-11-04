import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.naming.spi.DirObjectFactory;

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
