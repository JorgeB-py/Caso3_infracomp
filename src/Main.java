import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

public class Main {
    private static final int PUERTO = 3400;
    private static final String PUBLIC_KEY_FILE = "publicKey.ser";
    private static final String PRIVATE_KEY_FILE = "privateKey.ser";

    public static void main(String[] args) throws IOException {
        ArrayList<Integer> idCliente = new ArrayList<>();
        HashMap<Integer, Estados> paquetes = new HashMap<>();

        // Predefinir 32 paquetes con estados iniciales
        for (int i = 1; i <= 32; i++) {
            idCliente.add(i);
            if (i % 2 == 0) {
                paquetes.put(i+i, Estados.ENTREGADO);
            } else {
                paquetes.put(i+i, Estados.ENOFICINA);
            }
        }

        ServerSocket ss = null;
        boolean continuar = true;

        while (continuar) {
            System.out.println("Servidor iniciado. Selecciona una opción:");
            System.out.println("1. Generar pareja de llaves asimétricas");
            System.out.println("2. Ejecutar y crear delegados");

            Scanner sc = new Scanner(System.in);
            int opcion = sc.nextInt();

            if (opcion == 1) {
                generarLlaves();
            } else if (opcion == 2) {
                try {
                    ss = new ServerSocket(PUERTO);
                    System.out.println("Servidor escuchando en el puerto " + PUERTO);
                    
                    // Esperar conexiones y crear delegados
                    while (true) {
                        Socket socket = ss.accept();
                        ServidorDelegado servidor = new ServidorDelegado(idCliente, paquetes, socket);
                        servidor.start();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    if (ss != null) ss.close();
                }
            } else {
                System.out.println("Opción no válida, intenta de nuevo.");
            }
        }
    }

    private static void generarLlaves() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE))) {
                oos.writeObject(publicKey);
            }
            System.out.println("Llave pública guardada en " + PUBLIC_KEY_FILE);

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE))) {
                oos.writeObject(privateKey);
            }
            System.out.println("Llave privada guardada en " + PRIVATE_KEY_FILE);
            
            System.out.println("¡Pareja de llaves generada correctamente!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
