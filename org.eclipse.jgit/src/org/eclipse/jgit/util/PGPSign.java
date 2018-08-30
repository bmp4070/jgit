package org.eclipse.jgit.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
//import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.eclipse.jgit.annotations.NonNull;
import org.eclipse.jgit.lib.Constants;

/**
 * @author mprabhala
 * @since 5.1
 *
 */
public class PGPSign {
	private PGPSign() {
		throw new IllegalAccessError("Utility class");
	}

	/**
	 * ***************************************** A simple routine that opens a
	 * key ring file and loads the first available key suitable for encryption.
	 *
	 * @param instr
	 *            data stream containing the public key data
	 *
	 * @return the first public key found.
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKey(InputStream instr)
			throws PGPException {
		PGPPublicKeyRingCollection pgpPub;
		try {
			instr = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(instr);
			pgpPub = new PGPPublicKeyRingCollection(instr,
					new JcaKeyFingerprintCalculator());
		} catch (IOException | PGPException ex) {
			throw new PGPException("Failed to init public key ring", ex);
		}

		//
		// we just loop through the collection till we find a key suitable for
		// encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//

		Iterator keyRingIter = pgpPub.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

			Iterator keyIter = keyRing.getPublicKeys();
			while (keyIter.hasNext()) {
				PGPPublicKey key = (PGPPublicKey) keyIter.next();

				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException(
				"Can't find encryption key in key ring."); //$NON-NLS-1$
	}

	/**
	 * <p>
	 * Return the first suitable key for signing in the key ring collection. For
	 * this case we only expect there to be one key available for signing.
	 * </p>
	 * @return the first suitable PGP secret key found for signing
	 * @throws IOException
	 *             on I/O related errors
	 * @throws PGPException
	 *             on signing errors
	 */
	private static PGPSecretKey readSecretKey()
			throws IOException, PGPException {
		InputStream privStream = new ArmoredInputStream(
				Files.newInputStream(new File(
						"/Users/mprabhala/blt/.gnupg/D46432C1DE98F66004F0F608CDA2F392E27DF51B-blt.sec.asc")
								.toPath()));
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(privStream),
				new JcaKeyFingerprintCalculator());
		PGPSecretKey secKey = null;

		@SuppressWarnings("unchecked")
		Iterator<PGPSecretKeyRing> iter = pgpSec.getKeyRings();
		while (iter.hasNext() && secKey == null) {
			PGPSecretKeyRing keyRing = iter.next();

			@SuppressWarnings("unchecked")
			Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = keyIter.next();
				if (key.isSigningKey()) {
					secKey = key;
					break;
				}
			}
		}

		if (secKey != null) {
			return secKey;
		} else {
			throw new IllegalArgumentException(
					"Can't find signing key in key ring.");
		}
	}

	/**
	 * @param input
	 * @return buffer
	 * @throws IOException
	 */
	public static ByteArrayOutputStream signExternal(String input)
			throws IOException {
		@NonNull
		final BouncyCastleProvider provider = new BouncyCastleProvider();
		PGPSecretKey secretKey;
		try {
			secretKey = readSecretKey();
			PGPPrivateKey privKey;
			privKey = secretKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider(provider)
							.build("big_fahimi5".toCharArray()));
			PGPSignatureGenerator sigGenerator = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(
							secretKey.getPublicKey().getAlgorithm(),
							HashAlgorithmTags.SHA256).setProvider(provider));
			sigGenerator.init(PGPSignature.BINARY_DOCUMENT, privKey);

			ByteArrayOutputStream buffer = new ByteArrayOutputStream();

			try (ArmoredOutputStream aOut = new ArmoredOutputStream(buffer)) {
				BCPGOutputStream bOut = new BCPGOutputStream(aOut);
				sigGenerator.update(input.getBytes(Constants.CHARSET));
				sigGenerator.generate().encode(bOut);
			}
			return buffer;
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param args
	 * @throws PGPException
	 * @throws IOException
	 */
	// public static void main(String[] args) throws IOException, PGPException {
	// signExternal("Updated version"); //$NON-NLS-1$
	// }

}
