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
		if ("--gpg-sign".equals(alias) || "-S".equals(alias)) { //$NON-NLS-1$ //$NON-NLS-2$
			String keyID = params.getParameter(0);
			if (keyID == null || keyID.startsWith("-")) { //$NON-NLS-1$
				setter.addValue("default"); //$NON-NLS-1$
			} else {
				setter.addValue(keyID);
				return 1;
			}
		}
		return 0;

	}

}
