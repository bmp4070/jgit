/*
 * Copyright (C) 2018, Salesforce.
 * and other copyright owners as documented in the project's IP log.
 *
 * This program and the accompanying materials are made available
 * under the terms of the Eclipse Distribution License v1.0 which
 * accompanies this distribution, is reproduced below, and is
 * available at http://www.eclipse.org/org/documents/edl-v10.php
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 * - Neither the name of the Eclipse Foundation, Inc. nor the
 *   names of its contributors may be used to endorse or promote
 *   products derived from this software without specific prior
 *   written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.eclipse.jgit.lib;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;

import org.bouncycastle.openpgp.PGPException;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jgit.junit.JGitTestUtil;
import org.junit.Test;

public class GpgKeyManagerTest {

	byte[] keybox = Base64.decode(
			"AAAAIAEBAAJLQlhmAAAAAFvrMlJb6zJSAAAAAAAAAAAAAAWdAgEAAAAAAH4AAAULAAIAHJ"
					+ "ilYnoKh0 O9EUcexaX+6Axg/6TZAAAAIAAAAACqarw+GVmJzlUrKSDiQ/a7cjE7HAAAADw"
					+ "AAAAAAAAAAQAMAAAB ngAAACcAAAAAAAIABAAAAAAAAAAAAAAAAAAAAAAAAAAAW+syjQAA"
					+ "AACZAQ0EW+syYwEIAMMTl9Zipo EiKvpHNTNdqNjzEKG5lz99FHTUmLRCQk8mVMYmD6GIj"
					+ "RBbqJ/ggWMqButruxe9LZOO/33S6lZUXDEP hTOFTvFCleLZEVvGRM1FHxYNRG7UfBxi2M"
					+ "6PhBAnJnITsQw1uve5Wx6yewV/ErTyZOA+eIblcxnoTD GrTU7KwV2irjf+5F439/nTgT7"
					+ "Vcwh2E73RTVPwRyk2ByrALBgBtR540XpPHTm1T8IZcH1LpdJN7aM6 K6Q05owcQSDp76NP"
					+ "xuCzoMNO4XFqLs1BtddtVBVW1tCt2+C2sg0U0Vp9j8tUm0qsICQ9RJkVtqeSTy gZRVzsn"
					+ "l1HcNkTTvix3l0AEQEAAbAMAABncGcBAAAAAAAAtCdNZWRoYSBCaGFyZ2F2IDxqb2huLmR"
					+ "v ZUBzYWxlc2ZvcmNlLmNvbT6wDAAAZ3BnAgAAAAAAAIkBVAQTAQgAPhYhBJilYnoKh0O9"
					+ "EUcexaX+6A xg/6TZBQJb6zJjAhsDBQkDwmcABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAA"
					+ "AoJEKX+6Axg/6TZB/oH /jLJS2KtAspgmQQEvYh4cfPvbgX9yhz+xMF5vsc4cFrrXQpiKN"
					+ "L392mJmWOhmG2QEvS9aOmNG//8yq DnUS0xqll4kfKQhLEFIycqk9jy6ZRPYRY05ZIge6Z"
					+ "5hJCW/7YeCSZB8lH1kF0WrZvvrmuVDF97/7kk ViugIUdGZLiiAlhhSUO3W7TsntiNmgbz"
					+ "3Ln8SFaauyzF5sa7NOOq2IxGk7nuA9Ee0xs7NAr4s4REht hQoXRUL6vYCHbJIhOt7x44+"
					+ "d8BfQiETARVKmcuHPyH6TKUfhGAFxP/FvQJJwmy5Mucb5nHgh6S2pQF Y8nh3qtvhIQz+1"
					+ "sLN2VS/nIzWinO4DiwBgAAZ3BnALkBDQRb6zJjAQgAwHOSU7eXB75eMsDvOGsFw/ W7lOc"
					+ "/W5FxntPTspptueDwv/fsvx7Za01meSB3QqJ7k4Z8MpN4eGGZ06IEJtsA6ikK+whPoVXAv"
					+ "nfU hy5Aj+LehmnNnqMyiuX17dJ3nSFMFngQfVNOvPMwgk2G8Svw3eotq3fFKMe+g1DFk8"
					+ "MryxPNAn2kN4 IaPzGPygzX4XdHreyu6R3X3QK5L4c9+Y9a+WR+cfXME/o2XACaVk5bRWS"
					+ "tCiboh9aPZeDopOc/r7Re VmnwukMBD9XZDFfI+V5/UXTG/Ri6+Eg6HOt8opKuFcuB6Hdy"
					+ "cidvJLqbIVH7OPuGdQd7ErNAvNJF01 3P8AWhbQARAQABiQE8BBgBCAAmFiEEmKViegqHQ"
					+ "70RRx7Fpf7oDGD/pNkFAlvrMmMCGwwFCQPCZwAA CgkQpf7oDGD/pNkK+Af/aR1xYNYkq0"
					+ "rjlScdauDKLZLeh/BdFc1jP9iDK2RIuVIDOoct4lh0Fv1gWs d1JtRChzEIxPN6ILq0S0X"
					+ "80w9F56P+pzwxwqQBRNwufdlH66IhnbciB+FO2XW8xcxm+KQOuhqOPsuY xWyXN9SNyHzm"
					+ "V+JIBw4EFdoKcKcx+3EQZZk7da5KvreOSJGjf5odfLrk31+HkIrqJPvHPECjU3SMWr 1eM"
					+ "Nd4htlVvF9RK9Npz2zbO12l6sdnYBl36fQK1TUCCdNirZeQXHMDfco9aiq80oH6Vw7R1W9"
					+ "RSc4L 9WvYMk5qw4ZXX5N+X2bakutPT4T9SoYhyDTJEVWiWntWKlZEabAGAABncGcA7hob"
					+ "G1HVoRVCz3HP1R zd7lygGOI=");

	byte[] valid_secret_keyring = Base64.decode(
			"KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOnJzYSgxOm4yNTc6AMMTl9Zi"
					+ "poEiKvpHNTNdqNjzEKG5lz99FHTUmLRCQk8mVMYmD6GIjRBbqJ/ggWMqButr"
					+ "uxe9LZOO/33S6lZUXDEPhTOFTvFCleLZEVvGRM1FHxYNRG7UfBxi2M6PhBAn"
					+ "JnITsQw1uve5Wx6yewV/ErTyZOA+eIblcxnoTDGrTU7KwV2irjf+5F439/nT"
					+ "gT7Vcwh2E73RTVPwRyk2ByrALBgBtR540XpPHTm1T8IZcH1LpdJN7aM6K6Q0"
					+ "5owcQSDp76NPxuCzoMNO4XFqLs1BtddtVBVW1tCt2+C2sg0U0Vp9j8tUm0qs"
					+ "ICQ9RJkVtqeSTygZRVzsnl1HcNkTTvix3l0pKDE6ZTM6AQABKSg5OnByb3Rl"
					+ "Y3RlZDI1Om9wZW5wZ3AtczJrMy1zaGExLWFlcy1jYmMoKDQ6c2hhMTg6i3T5"
					+ "AyCdu8k4OjI1ODEwOTQ0KTE2Os4mjTdITEWYyLmUKghxhdwpNzIwOgcD0qf5"
					+ "vtkIYAsIAQKoqKSxjBdPFQHQ8YQrrSh3rMlPidPi9p/ob+KZDOd1FGPmwOPZ"
					+ "mrC908p6VZ4W/NYiXv7mlZ0VHOr2z9D0wsUTuCnnGAIrN5Zi1WJNufK6vQOU"
					+ "YrKhA8ijs5Il4D7z2s2rmhzyN6x++sl7QVxlrwBbDkWxCgbiOL373iUWx0V3"
					+ "OEwv47J/oifBfQNcX8UMv0QY83pZ3ZAYx7E4GHOEYNRnBqKVsLZVyL7Wjpxo"
					+ "QCzf35tNxOkZMn9pJv/trdtrj6FQfeL98vyzjEtb1WnsEk5YxM4pvnHiyfmB"
					+ "m1pQyHj6ORsi/TMvzvkY2gsVfuqBsVr2Re/QD/iSgdrmEpgg8s/9YRe7aTFH"
					+ "hfc4I3lJxotSdCLtuoAN3a9JdZwxND6LWW5vODtLhNUZpGysQ8lRku9w3ubz"
					+ "/qCnY0mU1k8UcZUfnwqU7Tw3rrkf8hspiB7iEkoiR7LyElK85TdQ5CNofbaB"
					+ "UTGpmeE/Wi6WFtq1/a9OjkFdLscGKjPG5cTkHftk2cBPAlISXYFJVzIn7J1N"
					+ "A/MSLYDXyaHKyem+JxFrrlKjJHdvAkrjv9ec25HYdOCzltNbAWNw9FB638pZ"
					+ "HrEv360pgpEgtwcifk1+qjH3GY99tRZKc9JVp9rw+VrjNdqRK+77LLyDGuKa"
					+ "8VpVCV++XnPUQci8CuGpP+sRfeKdr6TOYUfO0fM3OXiIpvQApJPowJfaUfPt"
					+ "AZBNXqzA357zsz+LNTXcPORU0L1tVKXq+fLn17S6kGuZqIi/vbz5qU2U10qa"
					+ "u3B2dhbC3GEtjpxFwaFQ6pFtfL5vTLmzxD8m1iMrcrBw/uCK6UjyRW0o299+"
					+ "efcBeUdeB6ciDReTEEuDIbecxFEG8/8Zob5MRJ6xx+xBTetnE7Y4DQKnHRUo"
					+ "e9h3vYe4dR/1Xaj/YFWaQ4HAQF3MV55Ga2lbszjo3GXRZMaOVswi6ikoMTI6"
					+ "cHJvdGVjdGVkLWF0MTU6MjAxODExMTNUMjAyMjM2KSkp");

	byte[] invalid_secret_keyring = Base64.decode(
			"KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOnJzYSgxOm4yNTc6AMMTl9Zi"
					+ "poEiKvpHNTNdqNjzEKG5lz99FHTUmLRCQk8mVMYmD6GIjRBbqJ/ggWMqButr"
					+ "uxe9LZOO/33S6lZUXDEPhTOFTvFCleLZEVvGRM1FHxYNRG7UfBxi2M6PhBAn"
					+ "JnITsQw1uve5Wx6yewV/ErTyZOA+eIblcxnoTDGrTU7KwV2irjf+5F439/nT"
					+ "gT7Vcwh2E73RTVPwRyk2ByrALBgBtR540XpPHTm1T8IZcH1LpdJN7aM6K6Q0"
					+ "5owcQSDp76NPxuCzoMNO4XFqLs1BtddtVBVW1tCt2+C2sg0U0Vp9j8tUm0qs"
					+ "ICQ9RJkVtqeSTygZRVzsnl1HcNkTTvix3l0pKDE6ZTM6AQABKSg5OnByb3Rl"
					+ "Y3RlZDI1Om9wZW5wZ3AtczJrMy1zaGExLWFlcy1jYmMoKDQ6c2hhMTg6i3T5"
					+ "AyCdu8k4OjI1ODEwOTQ0KTE2Os4mjTdITEWYyLmUKghxhdwpNzIwOgcD0qf5"
					+ "vtkIYAsIAQKoqKSxjBdPFQHQ8YQrrSh3rMlPidPi9p/ob+KZDOd1FGPmwOPZ"
					+ "mrC908p6VZ4W/NYiXv7mlZ0VHOr2z9D0wsUTuCnnGAIrN5Zi1WJNufK6vQOU"
					+ "YrKhA8ijs5Il4D7z2s2rmhzyN6x++sl7QVxlrwBbDkWxCgbiOL373iUWx0V3"
					+ "OEwv47J/oifBfQNcZ8UMv0QY83pZ3ZAYx7E4GHOEYNRnBqKVsLZVyL7Wjpxo"
					+ "QCzf35tNxOkZMn9pJv/trdtrj6FQfeL98vyzjEtb1WnsEk5YxM4pvnHiyfmB"
					+ "m1pQyHj6ORsi/TMvzvkY2gsVfuqBsVr2Re/QD/iSgdrmEpgg8s/9YRe7aTFH"
					+ "hfc4I3lJxotSdCLtuoAN3a9JdZwxND6LWW5vODtLhNUZpGysQ8lRku9w3ubz"
					+ "/qCnY0mU1k8UcZUfnwqU7Tw3rrkf8hspiB7iEkoiR7LyElK85TdQ5CNofbaB"
					+ "UTGpmeE/Wi6WFtq1/a9OjkFdLscGKjPG5cTkHftk2cBPAlISXYFJVzIn7J1N"
					+ "A/MSLYDXyaHKyem+JxFrrlKjJHdvAkrjv9ec25HYdOCzltNbAWNw9FB638pZ"
					+ "HrEv360pgpEgtwcifk1+qjH3GY99tRZKc9JVp9rw+VrjNdqRK+77LLyDGuKa"
					+ "8VpVCV++XnPUQci8CuGpP+sRfeKdr6TOYUfO0fM3OXiIpvQApJPowJfaUfPt"
					+ "AZBNXqzA357zsz+LNTXcPORU0L1tVKXq+fLn17S6kGuZqIi/vbz5qU2U10qa"
					+ "u3B2dhbC3GEtjpxFwaFQ6pFtfL5vTLmzxD8m1iMrcrBw/uCK6UjyRW0o299+"
					+ "efcBeUdeB6ciDReTEEuDIbecxFEG8/8Zob5MRJ6xx+xBTetnE7Y4DQKnHRUo"
					+ "e9h3vYe4dR/1Xaj/YFWaQ4HAQF3MV55Ga2lbszjo3GXRZMaOVswi6ikoMTI6"
					+ "cHJvdGVjdGVkLWF0MTU6MjAxODExMTNUMjAyMjM2KSkp");

	byte[] EXPECTED_COMMIT_BUFFER = Base64.decode(
			"LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0tLS0KIFZlcnNpb246IEJDUEcg"
					+ "djEuNjAKIAogaVFFY0JBQUJDQUFHQlFKYjhvS1pBQW9KRUtYKzZBeGcvNlRa"
					+ "Vm1JSC9ScGRKaklsUUIyenp3OE9qQXh0STg1eQogaTJadVh3RFdrbnNqSDFL"
					+ "NkpVMmEwQWZ3SFhCYnhEd0xYaVdibHZVaVZJV0txK1RIYWFEQnZjUkIxOFl4"
					+ "THMzYQogbk9JTitjQUFFQjBXWnVXRm01cVJzekFiYWs2MGlGc3V0VE9Bdlpx"
					+ "NkFsR3BoY0t1ZGV0TDF5bFE0cGlmUUZ0VgogNU5iU1VVUkRsbVBLeUdPc1g2"
					+ "UURGdDB0ZFBZT1dYdzJpTzBTUlpMQ3N5TDlsRW4rakdoY3F0OUhQKzZVdDhW"
					+ "TwogUlJLOG83MEZtZEdUcHNGaDF5aHRmK1pkempDU1BWMlRQS0kxdldFckpo"
					+ "d09pZ3JkWEZZcjN4QWJuYTc5UGdhbwogamF0b2lrS283SmlYZGFPVk9oZmR3"
					+ "N0VUOThZaHBlWVBpaVJKdElUNzhaRG9YcXl4alhBTko2ZWRWd2RM");

	private final String EXPECTED_GPG_KEYID = "A5FEE80C60FFA4D9";

	private final String PASSPHRASE = "JGitAuth1";

	private final String FAKE_GPG_SECRET_FILE = "fake-secring.gpg";

	private final String INVALID_GPG_SECRET_FILE = "invalid-secring.gpg";

	private static Path pathOf(String name) {
		return JGitTestUtil.getTestResourceFile(name).toPath();
	}

	@Test
	public void testFindPublicKeyFromKeyBox() throws IOException {
		PGPPublicKey publicKey = GpgKeyManager.findPublicKey(
				EXPECTED_GPG_KEYID, new ByteArrayInputStream(keybox));
		assertEquals(EXPECTED_GPG_KEYID,
				Long.toHexString(publicKey.getKeyID()).toUpperCase());
	}

	@Test
	public void isNullWhenSigningKeyNotKeyBox() throws IOException {
		String faultyGpgKeyId = "54EF958B45D43675";
		PGPPublicKey publicKey = GpgKeyManager.findPublicKey(
				faultyGpgKeyId, new ByteArrayInputStream(keybox));
		assertNull(publicKey);
	}

	@Test
	public void testFindSecretKeyFromKeyFile() throws Exception {
		PGPPublicKey publicKey = GpgKeyManager.findPublicKey(
				EXPECTED_GPG_KEYID, new ByteArrayInputStream(keybox));
		PGPSecretKey secretKey = GpgKeyManager.findSecretKey(
				new ByteArrayInputStream(valid_secret_keyring),
				new JcaPGPDigestCalculatorProviderBuilder()
					.build(), new JcePBEProtectionRemoverFactory(
						PASSPHRASE.toCharArray()),
				publicKey);
		assertEquals(EXPECTED_GPG_KEYID,
				Long.toHexString(secretKey.getKeyID()).toUpperCase());
	}

	@Test
	public void isNullWhenSecretKeyNotInKeyFile() throws Exception {
		PGPPublicKey publicKey = GpgKeyManager.findPublicKey(
				EXPECTED_GPG_KEYID, new ByteArrayInputStream(keybox));
		assertNull(GpgKeyManager.findSecretKey(
				new ByteArrayInputStream(invalid_secret_keyring),
				new JcaPGPDigestCalculatorProviderBuilder().build(),
				new JcePBEProtectionRemoverFactory(PASSPHRASE.toCharArray()),
				publicKey));
	}

	@Test
	public void testGetPrivateKey() throws Exception {
		PGPSecretKey secretKey = new GpgKeyManager(pathOf(FAKE_GPG_SECRET_FILE))
				.findSecretKey(EXPECTED_GPG_KEYID, PASSPHRASE);
		assertEquals(EXPECTED_GPG_KEYID,
				Long.toHexString(secretKey.getPublicKey().getKeyID())
						.toUpperCase());
	}

	@Test(expected = PGPException.class)
	public void isNullWhenInvalidKeyFile() throws Exception {
		new GpgKeyManager(pathOf(INVALID_GPG_SECRET_FILE))
				.findSecretKey(EXPECTED_GPG_KEYID, PASSPHRASE);
	}

	@Test
	public void testSignPayload() throws Exception {
		GpgKeyManager keyManager = new GpgKeyManager(
				pathOf(FAKE_GPG_SECRET_FILE));
		PGPSecretKey secretKey = keyManager
				.findSecretKey(EXPECTED_GPG_KEYID, PASSPHRASE);
		byte[] signedData = keyManager.signPayload("JGit Commit signer", EXPECTED_GPG_KEYID,
				PASSPHRASE);
		assertFalse(keyManager.verifySignature(signedData,
				secretKey.getPublicKey(),
				"This content is not signed".getBytes()));
		assertTrue(keyManager.verifySignature(
				signedData,
				secretKey.getPublicKey(),
				"JGit Commit signer".getBytes()
		));

	}
}
