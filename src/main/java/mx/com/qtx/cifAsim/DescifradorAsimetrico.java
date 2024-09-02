package mx.com.qtx.cifAsim;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class DescifradorAsimetrico {

	public static void main(String[] args) throws Exception {
		// Generar par de claves (como en los pasos anteriores)
		KeyPairGenerator generadorParLlaves = KeyPairGenerator.getInstance("RSA");
		generadorParLlaves.initialize(2048);
		KeyPair parLlaves = generadorParLlaves.generateKeyPair();
		
		PublicKey llavePublica = parLlaves.getPublic();
		PrivateKey llavePrivada = parLlaves.getPrivate();
		
		test_CifrarConPublica_DescifrarConPrivada(llavePublica, llavePrivada);
		test_CifrarConPrivada_DescifrarConPublica(llavePublica, llavePrivada);

	}

	private static void test_CifrarConPrivada_DescifrarConPublica(PublicKey llavePublica, PrivateKey llavePrivada)
			throws Exception {
		System.out.println("\ntest_CifrarConPrivada_DescifrarConPublica()\n");
		// Mensaje original
		String mensaje = "Este es otro mensaje secreto...";
		System.out.println("mensaje:" + mensaje);
		
		// Cifrar el mensaje
		byte[] mensajeCifrado = CifradorAsimetrico.cifrarConLlavePrivada(mensaje, llavePrivada);
		System.out.println("mensajeCifrado:" + new String(mensajeCifrado));

		// Descifrar el mensaje
		String mensajeDescifrado = descifrarConLlavePublica(mensajeCifrado, llavePublica);
		System.out.println("Mensaje descifrado: " + mensajeDescifrado);
	}

	private static void test_CifrarConPublica_DescifrarConPrivada(PublicKey llavePublica, PrivateKey llavePrivada)
			throws Exception {
		System.out.println("\ntest_CifrarConPublica_DescifrarConPrivada()\n");
		// Mensaje original
		String mensaje = "Este es un mensaje secreto";
		System.out.println("mensaje:" + mensaje);
		
		// Cifrar el mensaje
		byte[] mensajeCifrado = CifradorAsimetrico.cifrarConLlavePublica(mensaje, llavePublica);
		System.out.println("mensajeCifrado:" + new String(mensajeCifrado));
		
		// Descifrar el mensaje
		String mensajeDescifrado = descifrarConLlavePrivada(mensajeCifrado, llavePrivada);
		System.out.println("Mensaje descifrado: " + mensajeDescifrado);
	}

	public static String descifrarConLlavePrivada(byte[] msjCifrado, PrivateKey llavePrivada) throws Exception {
		// Instancia de Cipher para descifrar con RSA
		Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cifrador.init(Cipher.DECRYPT_MODE, llavePrivada);
		
		// Descifrar el mensaje
		byte[] msjDescifrado = cifrador.doFinal(msjCifrado);
		return new String(msjDescifrado, StandardCharsets.UTF_8);
	}
	
	private static String descifrarConLlavePublica(byte[] mensajeCifrado, PublicKey llavePublica) 
			              throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
			                     NoSuchPaddingException, InvalidKeyException {
		// Instancia de Cipher para descifrar con RSA
		Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cifrador.init(Cipher.DECRYPT_MODE, llavePublica);
		
		// Descifrar el mensaje
		byte[] msjDescifrado = cifrador.doFinal(mensajeCifrado);
		return new String(msjDescifrado, StandardCharsets.UTF_8);
	}

}

