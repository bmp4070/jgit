package org.eclipse.jgit.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.gpg.SExprParser;
import org.bouncycastle.gpg.keybox.KeyBlob;
import org.bouncycastle.gpg.keybox.KeyBox;
import org.bouncycastle.gpg.keybox.KeyInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.eclipse.jgit.annotations.NonNull;

/**
 * @author mprabhala
 * @since 5.2
 *
 */
@SuppressWarnings("restriction")
public class PGPSign {

	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray(); //$NON-NLS-1$

	@SuppressWarnings("nls")
	private static final Path DEFAULT_KEYRING_PATH = Paths
			.get(System.getProperty("user.home"), ".gnupg", "pubring.kbx");

	private static final Path DEFAULT_SECRET_KEY_DIR = Paths.get(
			System.getProperty("user.home"), ".gnupg", "private-keys-v1.d");

	private PGPSign() {
		throw new IllegalAccessError("PGP Utility class"); //$NON-NLS-1$
	}

	private static PGPSecretKey findSecretKey(PGPPublicKey publicKey,
			String passphrase) {

		PGPDigestCalculatorProvider calculatorProvider;
		PGPSecretKey secretKey;
		try {
			calculatorProvider = new JcaPGPDigestCalculatorProviderBuilder()
					.build();
			PBEProtectionRemoverFactory passphraseProvider = new JcePBEProtectionRemoverFactory(
					passphrase.toCharArray());
			try (Stream<Path> keyFiles = Files.walk(DEFAULT_SECRET_KEY_DIR)) {
				for (Path keyFile : keyFiles.filter(Files::isRegularFile)
						.collect(Collectors.toList())) {
					secretKey = findSecretKey(
							new BufferedInputStream(
									Files.newInputStream(keyFile)),
							calculatorProvider, passphraseProvider, publicKey);
					if (secretKey != null) {
						return secretKey;
					}

				}
			}
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}

	private static PGPSecretKey findSecretKey(InputStream secretStream,
			PGPDigestCalculatorProvider calculatorProvider,
			PBEProtectionRemoverFactory passphraseProvider,
			PGPPublicKey publicKey) {
		try {
			return new SExprParser(calculatorProvider).parseSecretKey(
					secretStream, passphraseProvider, publicKey);
		} catch (PGPException e) {
			// return null when secret key does not match public key
			return null;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Finds publicKey associated with keyID provided from input stream
	 *
	 * @param in
	 * @param signingKey
	 * @return publicKey
	 * @throws IOException
	 */
	public static PGPPublicKey findPublicKey(InputStream in, String signingKey)
			throws IOException {
		KeyBox keyBox = new KeyBox(in,
				new JcaKeyFingerprintCalculator());
		Iterator<KeyBlob> keyBlobs = keyBox.getKeyBlobs().listIterator();
		System.out.println(keyBlobs.hasNext());
		PGPPublicKeyRing keyRing = null;
		PGPPublicKey publicKey = null;
		while (keyBlobs.hasNext() && publicKey == null) {
			KeyBlob keyBlob = keyBlobs.next();
			Iterator<KeyInformation> keyInformations = keyBlob
					.getKeyInformation().listIterator();
			while (keyInformations.hasNext()) {
				KeyInformation keyInfo = keyInformations.next();
				System.out.println(BytesToHex(keyInfo.getKeyID()));
				if (signingKey.equals(BytesToHex(keyInfo.getKeyID()))) {
					keyRing = new PGPPublicKeyRing(keyBlob.getKeyBytes(),
							new JcaKeyFingerprintCalculator());
					publicKey = keyRing.getPublicKey();
					break;
				}
			}
		}
		return publicKey;
	}

	private static PGPPublicKey findPublicKey(String signingKey)
			throws IOException {
		InputStream keyStream = new BufferedInputStream(
				Files.newInputStream(DEFAULT_KEYRING_PATH));
		return findPublicKey(keyStream, signingKey);
	}

	/**
	 * @param input
	 * @param signingkey
	 * @param passphrase
	 * @return buffer
	 * @throws IOException
	 */
	public static byte[] signPayload(String input, String signingkey,
			String passphrase)
			throws IOException {
		@NonNull
		final BouncyCastleProvider provider = new BouncyCastleProvider();
		PGPPublicKey publicKey;
		PGPSecretKey secretKey;
		try {
			publicKey = findPublicKey(signingkey);
			secretKey = findSecretKey(publicKey, passphrase);
			PGPPrivateKey privateKey;
			privateKey = secretKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider(provider)
							.build(passphrase.toCharArray()));
			PGPSignatureGenerator sigGenerator = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(publicKey.getAlgorithm(),
							HashAlgorithmTags.SHA256).setProvider(provider));
			sigGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			byte[] gpgSignature = null;

			try (ArmoredOutputStream aOut = new ArmoredOutputStream(buffer)) {
				BCPGOutputStream bOut = new BCPGOutputStream(aOut);
				sigGenerator.update(input.getBytes(StandardCharsets.UTF_8));
				sigGenerator.generate().encode(bOut);
			}
			gpgSignature = StringUtils.replaceLFWithLFSpace(buffer.toString())
					.getBytes();
			System.out.println(new String(gpgSignature));
			return gpgSignature;
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param bytes
	 * @return hexString
	 */
	public static String BytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}
		return new String(hexChars);
	}

}
