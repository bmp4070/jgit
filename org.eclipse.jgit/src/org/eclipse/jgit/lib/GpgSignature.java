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

import java.io.Serializable;

/**
 * GPG signature class which uses keyID and passphrase to generate signature to
 * provided payload data
 *
 */
public class GpgSignature implements Serializable {
	private static final long serialVersionUID = 1L;

	private final String gpgSigningKeyId;

	private final String passphrase;

	private String buffer;

	/**
	 * @param aGpgSigningKeyId
	 * @param aPassphrase
	 */
	public GpgSignature(String aGpgSigningKeyId, String aPassphrase) {
		gpgSigningKeyId = aGpgSigningKeyId;
		passphrase = aPassphrase;
	}

	/**
	 * @param aGpgSigningKeyId
	 * @param aPassphrase
	 * @param aBuffer
	 */
	public GpgSignature(String aGpgSigningKeyId, String aPassphrase,
			String aBuffer) {
		gpgSigningKeyId = aGpgSigningKeyId;
		passphrase = aPassphrase;
		buffer = aBuffer;
	}

	/**
	 * Get last 16 digits of Gpg signing key
	 *
	 * @return gpgSigningKeyId
	 */
	public String getGpgSigningKeyId() {
		return gpgSigningKeyId;
	}

	/**
	 * Get passphrase for Gpg signature
	 *
	 * @return passphrase
	 */
	public String getPassphrase() {
		return passphrase;
	}

	/**
	 * Using signingKey and passphrase obtain key pair, generate signature for
	 * the payload provided.
	 *
	 * @param payload
	 */
	public void setBuffer(String payload) {
		buffer = new GpgKeyManager().signPayload(payload, gpgSigningKeyId,
				passphrase);
	}

	/**
	 * Return signature in string format
	 *
	 * @return signature
	 */
	public String toExternalString() {
		return buffer;
	}

	/**
	 * Return signature byte-array
	 *
	 * @return signature
	 */
	public byte[] getBytes() {
		return buffer.getBytes();
	}

}
