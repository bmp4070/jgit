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

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.eclipse.jgit.annotations.NonNull;

/**
 * @author mprabhala
 * @since 5.2
 *
 */
public class PGPSign {

	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray(); //$NON-NLS-1$

	private static final Path DEFAULT_SECRET_KEY_PATH = Paths
			.get(System.getProperty("user.home"), ".gnupg", "secring.gpg");

	private PGPSign() {
		throw new IllegalAccessError("PGP Utility class"); //$NON-NLS-1$
	}

	/**
	 * <p>
	 * Return the first suitable key for signing in the key ring collection. For
	 * this case we only expect there to be one key available for signing.
	 * </p>
	 * @param signingkey
	 *
	 * @return the first suitable PGP secret key found for signing
	 * @throws IOException
	 *             on I/O related errors
	 * @throws PGPException
	 *             on signing errors
	 */
	private static PGPSecretKey findSecretKey(String signingkey)
			throws IOException, PGPException {
		InputStream secStream = new BufferedInputStream(
				Files.newInputStream(DEFAULT_SECRET_KEY_PATH));
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(secStream),
				new JcaKeyFingerprintCalculator());
		PGPSecretKey secKey = null;

		@SuppressWarnings("unchecked")
		Iterator<PGPSecretKeyRing> keyrings = pgpSec.getKeyRings();
		while (keyrings.hasNext() && secKey == null) {
			PGPSecretKeyRing keyRing = keyrings.next();

			@SuppressWarnings("unchecked")
			Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = keyIter.next();
				String fingerprint = BytesToHex(key.getPublicKey().getFingerprint());
				if (fingerprint.endsWith(signingkey)) {
					secKey = key;
					break;
				}
				System.out.println(key);
			}
		}

		if (secKey != null) {
			return secKey;
		} else {
			throw new IllegalArgumentException(
					"Cannot find signing key in key ring.");
		}
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
		PGPSecretKey secretKey;
		try {
			secretKey = findSecretKey(signingkey);
			PGPPrivateKey privKey;
			privKey = secretKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider(provider)
							.build(passphrase.toCharArray()));
			PGPSignatureGenerator sigGenerator = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(
							secretKey.getPublicKey().getAlgorithm(),
							HashAlgorithmTags.SHA256).setProvider(provider));
			sigGenerator.init(PGPSignature.BINARY_DOCUMENT, privKey);

			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			byte[] gpgSignature = null;

			try (ArmoredOutputStream aOut = new ArmoredOutputStream(buffer)) {
				BCPGOutputStream bOut = new BCPGOutputStream(aOut);
				sigGenerator.update(input.getBytes(StandardCharsets.UTF_8));
				sigGenerator.generate().encode(bOut);
			}
			gpgSignature = StringUtils.replaceLFWithLFSpace(buffer.toString())
					.getBytes();
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

	/**
	 * @param args
	 */
	/*
	 * public static void main(String[] args) { try {
	 * signPayload("this is version.txt", "D8F8D96C45C7EB33",
	 * "affectionate_hatton8"); } catch (IOException e) { // TODO Auto-generated
	 * catch block e.printStackTrace(); } }
	 */
}
