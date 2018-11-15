package org.eclipse.jgit.lib;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jgit.junit.JGitTestUtil;
import org.junit.Test;

public class GpgKeyManagerTest {

	byte[] KEYBOX = Base64.decode(
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

	byte[] VALID_SECRET_KEYRING = Base64.decode(
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

	byte[] INVALID_SECRET_KEYRING = Base64.decode(
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

	private final String EXPECTED_GPG_KEYID = "A5FEE80C60FFA4D9";

	private final String PASSPHRASE = "JGitAuth1";

	private final String FAKE_GPG_SECRET_FILE = "fake-secring.gpg";

	private static Path pathOf(String name) {
		return JGitTestUtil.getTestResourceFile(name).toPath();
	}

	@Test
	public void testFindPublicKeyFromKeyBox() throws IOException {
		PGPPublicKey publicKey = GpgKeyManager.findPublicKey(
				EXPECTED_GPG_KEYID, new ByteArrayInputStream(KEYBOX));
		assertEquals(EXPECTED_GPG_KEYID,
				Long.toHexString(publicKey.getKeyID()).toUpperCase());
	}

	@Test
	public void isNullWhenSingingKeyNotKeyBox() throws IOException {
		String faultyGpgKeyId = "54EF958B45D43675";
		PGPPublicKey publicKey = GpgKeyManager.findPublicKey(
				faultyGpgKeyId, new ByteArrayInputStream(KEYBOX));
		assertNull(publicKey);
	}

	@Test
	public void testFindSecretKeyFromKeyFile() throws Exception {
		PGPPublicKey publicKey = GpgKeyManager.findPublicKey(
				EXPECTED_GPG_KEYID, new ByteArrayInputStream(KEYBOX));
		PGPSecretKey secretKey = GpgKeyManager.findSecretKey(
				new ByteArrayInputStream(VALID_SECRET_KEYRING),
				new JcaPGPDigestCalculatorProviderBuilder()
					.build(), new JcePBEProtectionRemoverFactory(
						PASSPHRASE.toCharArray()),
				publicKey);
		assertEquals(EXPECTED_GPG_KEYID,
				Long.toHexString(secretKey.getKeyID()).toUpperCase());
	}

	@Test
	public void isNullWhenSecretKeyNotinKeyFile() throws Exception {
		PGPPublicKey publicKey = GpgKeyManager.findPublicKey(
				EXPECTED_GPG_KEYID, new ByteArrayInputStream(KEYBOX));
		assertNull(GpgKeyManager.findSecretKey(
				new ByteArrayInputStream(INVALID_SECRET_KEYRING),
				new JcaPGPDigestCalculatorProviderBuilder().build(),
				new JcePBEProtectionRemoverFactory(PASSPHRASE.toCharArray()),
				publicKey));
	}

	@Test
	public void testGetPrivateKey() throws Exception {
		PGPSecretKey secretKey = GpgKeyManager.findSecretKey(EXPECTED_GPG_KEYID,
				PASSPHRASE, pathOf(FAKE_GPG_SECRET_FILE));
		assertEquals(EXPECTED_GPG_KEYID,
				Long.toHexString(secretKey.getPublicKey().getKeyID())
						.toUpperCase());
	}

}
