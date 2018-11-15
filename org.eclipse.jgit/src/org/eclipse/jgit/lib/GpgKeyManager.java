package org.eclipse.jgit.lib;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.regex.Pattern;
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
import org.eclipse.jgit.api.errors.JGitInternalException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
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
public class GpgKeyManager {

	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray(); //$NON-NLS-1$

	private static final Path DEFAULT_KEYBOX_PATH = Paths
			.get(System.getProperty("user.home"), ".gnupg", "pubring.kbx"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

	private static final Path DEFAULT_SECRET_KEY_DIR = Paths.get(
			System.getProperty("user.home"), ".gnupg", "private-keys-v1.d"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

	private static final Path DEFAULT_PGP_SECRET_KEY_PATH = Paths
			.get(System.getProperty("user.home"), ".gnupg", "secring.gpg"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

	private GpgKeyManager() {
		throw new IllegalAccessError("GPG Utility class"); //$NON-NLS-1$
	}

	private static PGPSecretKey findSecretKey(PGPPublicKey publicKey,
			String passphrase) throws PGPException {

		PGPDigestCalculatorProvider calculatorProvider;
		PGPSecretKey secretKey = null;
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
					break;
				}
				if (secretKey == null)
					throw new PGPException(
							"gpg failed to find associated secret key for public key: " //$NON-NLS-1$
									+ Long.toHexString(publicKey.getKeyID()));
				return secretKey;
			}
		} catch (PGPException | IOException e) {
			// TODO Auto-generated catch block
			throw new PGPException(
					"gpg failed to parse secret key file under directory " //$NON-NLS-1$
							+ DEFAULT_SECRET_KEY_DIR.toAbsolutePath()
									.toString());
		}
	}

	/**
	 * Find matching secretKey in key files associated to given public key
	 *
	 * @param secretStream
	 * @param calculatorProvider
	 * @param passphraseProvider
	 * @param publicKey
	 * @return secretKey
	 * @throws IOException
	 */
	public static PGPSecretKey findSecretKey(InputStream secretStream,
			PGPDigestCalculatorProvider calculatorProvider,
			PBEProtectionRemoverFactory passphraseProvider,
			PGPPublicKey publicKey) throws IOException {
		try {
			return new SExprParser(calculatorProvider).parseSecretKey(
					secretStream, passphraseProvider, publicKey);
		} catch (PGPException | ClassCastException e) {
			// return null when secret key does not match public key
			return null;
		}
	}

	/**
	 * <p>
	 * Return the first suitable key for signing in the key ring collection. For
	 * this case we only expect there to be one key available for signing.
	 * </p>
	 *
	 * @param signingkey
	 * @param secretStream
	 *
	 * @return the first suitable PGP secret key found for signing
	 * @throws IOException
	 *             on I/O related errors
	 * @throws PGPException
	 *             on signing errors
	 */
	private static PGPSecretKey findSecretKey(String signingkey,
			InputStream secretStream) throws IOException, PGPException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(secretStream),
				new JcaKeyFingerprintCalculator());
		PGPSecretKey secretKey = null;
		Iterator<PGPSecretKeyRing> keyrings = pgpSec.getKeyRings();
		while (keyrings.hasNext() && secretKey == null) {
			PGPSecretKeyRing keyRing = keyrings.next();
			PGPSecretKey key = null;
			Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				key = keyIter.next();
				String fingerprint = bytesToHex(
						key.getPublicKey().getFingerprint());
				if (fingerprint.endsWith(signingkey)) {
					secretKey = key;
					break;
				}
			}
		}
		if (secretKey != null) {
			return secretKey;
		} else {
			throw new PGPException(
					"gpg failed to find secret-key which matches provided keyID: " //$NON-NLS-1$
							+ signingkey);
		}
	}

	private static PGPSecretKey findSecretKey(String signingkey,
			String passphrase) throws IOException, PGPException {
		return findSecretKey(signingkey, passphrase, null);
	}

	/**
	 * Use pubring.kbx when available, if not fallback to secring.gpg or secret
	 * key path provided to parse and return secret key
	 *
	 * @param signingkey
	 * @param passphrase
	 * @param gpgSecretKeyPath
	 * @return secretKey
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPSecretKey findSecretKey(String signingkey,
			String passphrase, Path gpgSecretKeyPath)
			throws IOException, PGPException {
		PGPSecretKey secretKey = null;
		if (gpgSecretKeyPath != null) {
			secretKey = findSecretKey(signingkey, new BufferedInputStream(
					Files.newInputStream(gpgSecretKeyPath)));
		}
		else if (Files.exists(DEFAULT_KEYBOX_PATH)) {
			InputStream keyStream = new BufferedInputStream(
					Files.newInputStream(DEFAULT_KEYBOX_PATH));
			PGPPublicKey publicKey = findPublicKey(signingkey, keyStream);
			if (publicKey == null)
				throw new PGPException(
						"gpg failed to find public-key which matches provided keyID: " //$NON-NLS-1$
								+ signingkey);
			secretKey = findSecretKey(publicKey, passphrase);
		} else if (Files.exists(DEFAULT_PGP_SECRET_KEY_PATH)) {
			secretKey = findSecretKey(signingkey, new BufferedInputStream(
					Files.newInputStream(DEFAULT_PGP_SECRET_KEY_PATH)));
		} else {
			throw new PGPException(
					"gpg failed to find pubring.kbx or secring.gpg files"); //$NON-NLS-1$
		}
		return secretKey;
	}

	/**
	 * Finds publicKey associated with keyID provided from input stream
	 *
	 * @param in
	 * @param signingKey
	 * @return publicKey
	 * @throws IOException
	 */
	public static PGPPublicKey findPublicKey(String signingKey, InputStream in)
			throws IOException {
		KeyBox keyBox = new KeyBox(in, new JcaKeyFingerprintCalculator());
		PGPPublicKeyRing keyRing = null;
		PGPPublicKey publicKey = null;
		Iterator<KeyBlob> keyBlobs = keyBox.getKeyBlobs().listIterator();
		while (keyBlobs.hasNext() && publicKey == null) {
			KeyBlob keyBlob = keyBlobs.next();
			Iterator<KeyInformation> keyInformations = keyBlob
					.getKeyInformation().listIterator();
			while (keyInformations.hasNext()) {
				KeyInformation keyInfo = keyInformations.next();
				if (signingKey.equals(bytesToHex(keyInfo.getKeyID()))) {
					keyRing = new PGPPublicKeyRing(keyBlob.getKeyBytes(),
							new JcaKeyFingerprintCalculator());
					publicKey = keyRing.getPublicKey();
					break;
				}
			}
		}
		return publicKey;
	}

	/**
	 * Using singingKey and passphrase obtain key pair and using signature
	 * generator generate signature for the input provided.
	 *
	 * @param input
	 * @param signingkey
	 * @param passphrase
	 * @return gpgSignature
	 */
	public static byte[] signPayload(String input, String signingkey,
			String passphrase) {
		@NonNull
		final BouncyCastleProvider provider = new BouncyCastleProvider();
		PGPSecretKey secretKey;
		try {
			secretKey = findSecretKey(signingkey, passphrase);
			PGPPrivateKey privateKey = secretKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider(provider)
							.build(passphrase.toCharArray()));
			PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(
							secretKey.getPublicKey().getAlgorithm(),
							HashAlgorithmTags.SHA256).setProvider(provider));
			signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			byte[] gpgSignature = null;

			try (ArmoredOutputStream aOut = new ArmoredOutputStream(buffer)) {
				BCPGOutputStream bOut = new BCPGOutputStream(aOut);
				signatureGenerator
						.update(input.getBytes(StandardCharsets.UTF_8));
				signatureGenerator.generate().encode(bOut);
				gpgSignature = replaceLFWithLFSpace(buffer.toString())
						.getBytes();
			}
			return gpgSignature;
		} catch (PGPException | IOException e) {
			throw new JGitInternalException(e.getMessage(), e);
		}
	}

	/**
	 * Return hex string for bytes provided
	 *
	 * @param bytes
	 * @return hexString
	 */
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}
		return new String(hexChars);
	}

	/**
	 * Format BC provided signature according to GIT signature-format
	 * <p>
	 * Format doc here:
	 * https://github.com/git/git/blob/master/Documentation/technical/signature-format.txt#L79,L89
	 * </p>
	 *
	 * @param text
	 *            A string with line breaks
	 * @return text with line breaks and a space after new line
	 */
	public static String replaceLFWithLFSpace(final String text) {
		if (text == null) {
			return text;
		}
		Pattern lf = Pattern.compile("\n"); //$NON-NLS-1$
		return lf.matcher(text).replaceAll("\n "); //$NON-NLS-1$
	}

	/**
	 * @param args
	 */
	/*
	 * public static void main(String[] args) { try {
	 * signPayload("this is version.txt", "716B1D0DAD2CCB0A", "tallChoalla@9");
	 * } catch (IOException e) { // TODO Auto-generated e.printStackTrace(); } }
	 */

}
