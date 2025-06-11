package mx.com.qtx.cifSimetrico;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class CifradoSimetricoAES {

    private static final String ALGORITMO_AES = "AES";
    private static final String TRANSFORMACION = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128; // Longitud de autenticación (GCM)
    private static final int IV_LENGTH_BYTE = 12;   // Longitud de IV recomendada para GCM

    public static void main(String[] args) throws Exception {
        // 1. Generar clave secreta
        SecretKey clave = generarClaveAES(256);
        
        // Mensaje original
        String mensajeOriginal = "La criptografía protege la información confidencial";
        System.out.println("Mensaje original: " + mensajeOriginal);
        
        // 2. Cifrar
        DatosCifrados mensajeCifrado = cifrar(mensajeOriginal, clave);
        System.out.println("Initialization Vector (Base64): " + Base64.getEncoder().encodeToString(mensajeCifrado.iv()));
        System.out.println("Mensaje cifrado (Base64): " + 
            Base64.getEncoder().encodeToString(mensajeCifrado.textoCifrado()));
        
        // 3. Descifrar
        String mensajeDescifrado = descifrar(mensajeCifrado, clave);
        System.out.println("Mensaje descifrado: " + mensajeDescifrado);
    }

    // Generar clave AES de tamaño específico (128, 192, 256 bits)
    public static SecretKey generarClaveAES(int keySize) throws Exception {
        KeyGenerator generador = KeyGenerator.getInstance(ALGORITMO_AES);
        generador.init(keySize);
        return generador.generateKey();
    }

    // Cifrar texto usando AES-GCM
    public static DatosCifrados cifrar(String textoPlano, SecretKey clave) throws Exception {
        // Preparar cifrador
        Cipher cifrador = Cipher.getInstance(TRANSFORMACION);
        
        // Generar Vector de Inicialización(IV) aleatorio
        byte[] iv = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(iv);
        
        // Configurar cifrador en modo cifrado
        GCMParameterSpec parametros = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cifrador.init(Cipher.ENCRYPT_MODE, clave, parametros);
        
        // Cifrar texto
        byte[] bytesTexto = textoPlano.getBytes(StandardCharsets.UTF_8);
        byte[] textoCifrado = cifrador.doFinal(bytesTexto);
        
        return new DatosCifrados(textoCifrado, iv);
    }

    // Descifrar usando AES-GCM
    public static String descifrar(DatosCifrados datos, SecretKey clave) throws Exception {
        // Preparar cifrador
        Cipher cifrador = Cipher.getInstance(TRANSFORMACION);
        
        // Configurar cifrador en modo descifrado
        GCMParameterSpec parametros = new GCMParameterSpec(TAG_LENGTH_BIT, datos.iv());
        cifrador.init(Cipher.DECRYPT_MODE, clave, parametros);
        
        // Descifrar texto
        byte[] textoDescifrado = cifrador.doFinal(datos.textoCifrado());
        return new String(textoDescifrado, StandardCharsets.UTF_8);
    }

    // Record para almacenar datos cifrados + IV
    record DatosCifrados(byte[] textoCifrado, byte[] iv) {}
}