import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import javax.crypto.Cipher;
import java.security.SecureRandom;
import java.util.Base64;

public class Cliente{
    public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";
    public static final String PUBLIC_KEY_FILE = "publicKey.ser";
    private static final String CARACTERES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final SecureRandom random = new SecureRandom();
	
	public static void main(String[] args) throws IOException {
		
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		
		System.out.println("Comienza cliente");
		PublicKey publicKey = null;
		try {
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
            publicKey = (PublicKey) ois.readObject();
            System.out.println("Llave pública leída exitosamente.");

            escritor.println("SECINIT");
            String mensaje = generarCadena(16);
            String encodedMessage = cifrar(publicKey, mensaje, "RSA");
            escritor.println(encodedMessage);
            String respuesta = lector.readLine();
            if (respuesta.equals(mensaje)){
                escritor.println("OK");
            }else{
                escritor.println("ERROR");
            }
            
		}
		catch (Exception e) {
			e.printStackTrace();
		}




        
		
		socket.close();
		escritor.close();
		lector.close();
	}

    public static String generarCadena(int longitud) {
        StringBuilder sb = new StringBuilder(longitud);
        for (int i = 0; i < longitud; i++) {
            int indiceAleatorio = random.nextInt(CARACTERES.length());
            sb.append(CARACTERES.charAt(indiceAleatorio));
        }
        return sb.toString();
    }

    public static String cifrar(PublicKey llave, String mensaje, String algoritmo) {
        try {          
            byte[] R = null;
            Cipher cipher = Cipher.getInstance(algoritmo);
            cipher.init(Cipher.ENCRYPT_MODE, llave);
            R = cipher.doFinal(mensaje.getBytes());
            String encodedMessage = Base64.getEncoder().encodeToString(R);
            
            return encodedMessage;
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            return null;
        }
    }

}