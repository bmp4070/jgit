/*
 * Copyright (C) 2015, Andrey Loskutov <loskutov@gmx.de>
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
package org.eclipse.jgit.pgm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.eclipse.jgit.lib.CLIRepositoryTestCase;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.util.FS;
import org.eclipse.jgit.util.FS.ExecutionResult;
import org.eclipse.jgit.util.RawParseUtils;
import org.junit.Test;

public class CommitTest extends CLIRepositoryTestCase {

	private static final boolean IS_WINDOWS = System.getProperty("os.name")
			.toLowerCase().contains("windows");

	@Test
	public void testCommitPath() throws Exception {
		writeTrashFile("a", "a");
		writeTrashFile("b", "a");
		String result = toString(execute("git add a"));
		assertEquals("", result);

		result = toString(execute("git status -- a"));
		assertEquals(toString("On branch master", "Changes to be committed:",
				"new file:   a"), result);

		result = toString(execute("git status -- b"));
		assertEquals(toString("On branch master", "Untracked files:", "b"),
				result);

		result = toString(execute("git commit a -m 'added a'"));
		assertEquals(
				"[master 8cb3ef7e5171aaee1792df6302a5a0cd30425f7a] added a",
				result);

		result = toString(execute("git status -- a"));
		assertEquals("On branch master", result);

		result = toString(execute("git status -- b"));
		assertEquals(toString("On branch master", "Untracked files:", "b"),
				result);
	}

	@Test
	public void testCommitAll() throws Exception {
		writeTrashFile("a", "a");
		writeTrashFile("b", "a");
		String result = toString(execute("git add a b"));
		assertEquals("", result);

		result = toString(execute("git status -- a b"));
		assertEquals(toString("On branch master", "Changes to be committed:",
				"new file:   a", "new file:   b"), result);

		result = toString(execute("git commit -m 'added a b'"));
		assertEquals(
				"[master 3c93fa8e3a28ee26690498be78016edcb3a38c73] added a b",
				result);

		result = toString(execute("git status -- a b"));
		assertEquals("On branch master", result);
	}

	@Test
	public void testUnverifiedCommitSign() throws Exception {
		assumeFalse(IS_WINDOWS);
		String repoTarPath = System.getProperty("user.dir") + File.separator
				+ "tst-rsrc" + File.separator + "commit_sign_temp.tar";
		File repoPath = createTempDirectory("commit_sign_temp");

		decompress(repoTarPath, repoPath);
		Repository unverifiedSignDb = new FileRepositoryBuilder()
				.setWorkTree(repoPath).build();
		FS fs = unverifiedSignDb.getFS();

		ProcessBuilder builder = fs.runInShell("git", new String[] {
				"verify-commit", "5d4be77e6665845a8f2b7f4d10bc6a3150af0dab" });
		builder.directory(unverifiedSignDb.getWorkTree());
		builder.environment().put("HOME", fs.userHome().getAbsolutePath());
		ExecutionResult unverifiedResult = fs.execute(builder,
				new ByteArrayInputStream(new byte[0]));
		String unverifiedOutput = RawParseUtils
				.decode(unverifiedResult.getStderr().toByteArray());

		assertTrue(unverifiedOutput.contains("551C63EA924F5C3D"));
		assertTrue(unverifiedOutput.contains("No public key"));
	}

	@Test
	public void testVerifiedCommitSign() throws Exception {
		assumeFalse(IS_WINDOWS);
		String repoTarPath = System.getProperty("user.dir") + File.separator
				+ "tst-rsrc" + File.separator + "commit_sign_temp.tar";
		File repoPath = createTempDirectory("commit_sign_temp");

		decompress(repoTarPath, repoPath);
		System.out.println(repoPath.toString());
		String gnupgHome = getClass().getClassLoader().getResource("test_gnupg")
				.getPath();
		Repository verifiedSignDb = new FileRepositoryBuilder()
				.setWorkTree(repoPath).build();
		FS fs = verifiedSignDb.getFS();

		ProcessBuilder builder = fs.runInShell("git", new String[] {
				"verify-commit", "5d4be77e6665845a8f2b7f4d10bc6a3150af0dab" });
		builder.directory(verifiedSignDb.getWorkTree());
		builder.environment().put("HOME", fs.userHome().getAbsolutePath());
		builder.environment().put("GNUPGHOME", gnupgHome);
		ExecutionResult verifiedResult = fs.execute(builder,
				new ByteArrayInputStream(new byte[0]));
		String verifiedOutput = RawParseUtils
				.decode(verifiedResult.getStderr().toByteArray());

		assertTrue(verifiedOutput.contains("551C63EA924F5C3D"));
		assertTrue(verifiedOutput.contains("Good signature"));
	}

	public static void decompress(String in, File out) throws IOException {
		try (TarArchiveInputStream fin = new TarArchiveInputStream(
				new FileInputStream(in))) {
			TarArchiveEntry entry;
			while ((entry = fin.getNextTarEntry()) != null) {
				if (entry.isDirectory()) {
					continue;
				}
				File curfile = new File(out, entry.getName());
				File parent = curfile.getParentFile();
				if (!parent.exists()) {
					parent.mkdirs();
				}
				IOUtils.copy(fin, new FileOutputStream(curfile));
			}
		}
	}

}
