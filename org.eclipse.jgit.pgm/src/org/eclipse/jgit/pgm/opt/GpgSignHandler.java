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
package org.eclipse.jgit.pgm.opt;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.OptionDef;
import org.kohsuke.args4j.spi.Parameters;
import org.kohsuke.args4j.spi.Setter;
import org.kohsuke.args4j.spi.StringOptionHandler;

/**
 * Special handler for the <code>--gpg-sign</code> option of the
 * <code>commit</code> command.
 *
 * The following rules apply:
 * <ul>
 * <li>If no keyID is given, i.e. just <code>--gpg-sign</code> is passed, then
 * it is the same as <code>--gpg-sign=default</code></li>
 * </ul>
 * Default value is read from gitconfig
 *
 */

public class GpgSignHandler extends StringOptionHandler {

	/**
	 * <p>
	 * Constructor for GpgSignHandler.
	 * </p>
	 *
	 * @param parser
	 *            The parser to which this handler belongs.
	 * @param option
	 *            The annotation.
	 * @param setter
	 *            Object to be used for setting value.
	 */
	public GpgSignHandler(CmdLineParser parser, OptionDef option,
			Setter<? super String> setter) {
		super(parser, option, setter);
	}

	/** {@inheritDoc} */
	@Override
	public int parseArguments(Parameters params) throws CmdLineException {
		String alias = params.getParameter(-1);
		String keyID;
		if ("--gpg-sign".equals(alias) || "-S".equals(alias)) { //$NON-NLS-1$ //$NON-NLS-2$
			try {
				keyID = params.getParameter(0);
			} catch (CmdLineException e) {
				keyID = null;
			}
			if (keyID == null || keyID.startsWith("-")) { //$NON-NLS-1$
				setter.addValue("default");
			} else {
				setter.addValue(keyID);
				return 1;
			}
		}
		return 0;

	}

}
