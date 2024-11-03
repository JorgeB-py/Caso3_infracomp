import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;

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

            if(lector.readLine() == "OK"){
                System.out.println("Cliente autenticado");
            }else{
                System.out.println("Error en la autenticación");
                ois.close();
                ois2.close();
                throw new Exception("Error en la autenticación");
            }

            

            // Leer identificador de cliente y paquete

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
}
