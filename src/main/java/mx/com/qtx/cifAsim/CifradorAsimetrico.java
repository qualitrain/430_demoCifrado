package mx.com.qtx.cifAsim;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CifradorAsimetrico {

	public static void main(String[] args) throws Exception {
		
        KeyPairGenerator generadorParLlaves = KeyPairGenerator.getInstance("RSA");
        generadorParLlaves.initialize(2048);
        KeyPair parLlaves = generadorParLlaves.generateKeyPair();
        
        PublicKey llavePublica = parLlaves.getPublic();

        test_Cifrado_con_LlavePublica(llavePublica);
        
        PrivateKey llavePrivada = parLlaves.getPrivate();
        test_Cifrado_con_LlavePrivada(llavePrivada);
	}


	private static void test_Cifrado_con_LlavePublica(PublicKey llavePublica) throws Exception {
		System.out.println("\ntest_Cifrado_con_LlavePublica() ----------\n");
		String mensaje = "Este es un mensaje secreto";
        byte[] mensajeCifrado = cifrarConLlavePublica(mensaje, llavePublica);

        System.out.println("Mensaje cifrado: " + new String(mensajeCifrado));
	}

	private static void test_Cifrado_con_LlavePrivada(PrivateKey llavePrivada) throws Exception {
		System.out.println("\ntest_Cifrado_con_LlavePrivada() ----------\n");
		String mensaje = "Este es un mensaje secreto";
        byte[] mensajeCifrado = cifrarConLlavePrivada(mensaje, llavePrivada);

        System.out.println("Mensaje cifrado: " + new String(mensajeCifrado));
	}
	
	public static byte[] cifrarConLlavePublica(String textoPlano, PublicKey llavePublica) throws Exception {
		// Instancia de Cipher para cifrar con RSA
		Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cifrador.init(Cipher.ENCRYPT_MODE, llavePublica);
		
		// Cifrar el mensaje de texto
		byte[] msjCifrado = cifrador.doFinal(textoPlano.getBytes(StandardCharsets.UTF_8));
		return msjCifrado;
	}
	
	public static byte[] cifrarConLlavePrivada(String textoPlano, PrivateKey llavePrivada) throws Exception {
		// Instancia de Cipher para cifrar con RSA
		Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cifrador.init(Cipher.ENCRYPT_MODE, llavePrivada);
		
		// Cifrar el mensaje de texto
		byte[] msjCifrado = cifrador.doFinal(textoPlano.getBytes(StandardCharsets.UTF_8));
		return msjCifrado;
	}
}
