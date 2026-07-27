/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.pcodeCPort.slgh_compile;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.ErrorLogger;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import utilities.util.FileUtilities;

/**
 * Compiles deliberately-malformed sleigh specs and asserts on the diagnostics produced.
 * <p>
 * Nothing else tests the compiler's error messages. {@link SleighCompileOptionsTest} parses
 * command-line options without ever compiling, and the nightly {@code SleighCompileRegressionTest}
 * compiles the shipped languages and asserts that they <em>succeed</em>. So a diagnostic could stop
 * naming the thing it is about, or stop firing altogether, with no test noticing.
 * <p>
 * <b>Assertions here are deliberately loose.</b> Each lists the substrings a message must contain --
 * the offending name, and the numbers a reader needs -- never the whole message. Wording is a
 * judgement call that should stay cheap to revise; what must not regress is whether the message
 * identifies the problem well enough to act on.
 *
 * @see #compile(String) for why diagnostics have to be collected from two places at once
 */
public class SleighCompileDiagnosticsTest extends AbstractGenericTest {

	/**
	 * The preamble every fixture shares: the least sleigh accepts before it will look at a
	 * constructor. Two tokens of different sizes are declared because the token- and
	 * pattern-combining diagnostics need a mismatched pair to provoke them, and one register is
	 * deliberately an odd size so operand widths can be made to disagree.
	 */
	private static final String PREAMBLE = """
			define endian=little;
			define alignment=1;
			define space ram type=ram_space size=4 default;
			define space register type=register_space size=4;
			define register offset=0x0 size=4 [ r0 r1 r2 sp pc ];
			define register offset=0x20 size=6 [ oddSized ];
			define token byteTok(8) op8=(0,7) sub8=(0,3);
			define token wordTok(16) op16=(0,15);
			""";

	/**
	 * Collects what the compiler logs, keeping errors and warnings apart.
	 * <p>
	 * Capturing at the {@link Msg} level rather than by overriding
	 * {@link SleighCompile#reportError} is what makes this work: the compiler logs through
	 * <em>three</em> different routes, and only two of them go through the reporter. See
	 * {@link SleighCompileDiagnosticsTest#compile(String)}.
	 */
	private static class CapturingLogger implements ErrorLogger {
		private final List<String> errors = new ArrayList<>();
		private final List<String> warnings = new ArrayList<>();

		void clear() {
			errors.clear();
			warnings.clear();
		}

		@Override
		public void error(Object originator, Object message) {
			errors.add(String.valueOf(message));
		}

		@Override
		public void error(Object originator, Object message, Throwable throwable) {
			errors.add(String.valueOf(message));
		}

		@Override
		public void warn(Object originator, Object message) {
			warnings.add(String.valueOf(message));
		}

		@Override
		public void warn(Object originator, Object message, Throwable throwable) {
			warnings.add(String.valueOf(message));
		}

		@Override
		public void info(Object originator, Object message) {
			// not a diagnostic
		}

		@Override
		public void info(Object originator, Object message, Throwable throwable) {
			// not a diagnostic
		}

		@Override
		public void debug(Object originator, Object message) {
			// not a diagnostic
		}

		@Override
		public void debug(Object originator, Object message, Throwable throwable) {
			// not a diagnostic
		}

		@Override
		public void trace(Object originator, Object message) {
			// not a diagnostic
		}

		@Override
		public void trace(Object originator, Object message, Throwable throwable) {
			// not a diagnostic
		}
	}

	private final CapturingLogger logger = new CapturingLogger();

	/**
	 * Diverts logging for the rest of this class. Nothing restores it, matching what every other
	 * spy-logger test in the tree does ({@code ColorValueTest}, {@code OptionsTest} and friends):
	 * {@link Msg} exposes no way to read the current logger back, and the test tasks set
	 * {@code forkEvery = 1}, so one JVM per test class already provides the isolation.
	 */
	@Before
	public void setUp() {
		Msg.setErrorLogger(logger);
	}

	/**
	 * The outcome of one compilation.
	 * <p>
	 * Errors and warnings are kept apart on purpose. Compiling anything at all emits routine
	 * warnings -- "N unnecessary extensions/truncations were converted to copies" among them -- and
	 * an assertion searching one combined list will happily match a substring of one of those and
	 * pass while the diagnostic under test never fired at all. Asserting against {@code errors}
	 * alone removes that whole class of false positive.
	 *
	 * @param returnCode what {@code run_compilation} returned; 0 only on success
	 * @param errors logged errors, plus anything the compiler wrote to {@code System.err}
	 * @param warnings logged warnings
	 */
	protected record Diagnostics(int returnCode, List<String> errors, List<String> warnings) {

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder("rc=").append(returnCode);
			errors.forEach(e -> sb.append("\n  ERROR   ").append(e));
			warnings.forEach(w -> sb.append("\n  WARNING ").append(w));
			return sb.toString();
		}
	}

	/**
	 * Compiles {@link #PREAMBLE} plus {@code body} and returns what the compiler said.
	 * <p>
	 * Diagnostics have to be collected from two places, because the compiler emits them by three
	 * different routes:
	 * <ol>
	 * <li>{@link SleighCompile#reportError} and {@code reportWarning}, which log via {@link Msg};
	 * <li>ANTLR lexer and parser errors, which call {@code emitErrorMessage} and so reach
	 * {@link Msg} directly, never passing through the reporter or its error count;
	 * <li>pattern-building errors, which do not log at all -- {@code buildPatterns} hands
	 * {@code System.err} straight to {@code root.buildPattern(...)}, so they bypass the reporter,
	 * lose their source location on the way, and can only be seen by redirecting the stream.
	 * </ol>
	 * Hooking {@link Msg} covers the first two; the redirect covers the third. Both land in
	 * {@code errors}, so these tests keep passing unchanged if that third route is ever plumbed
	 * through the reporter properly.
	 */
	protected Diagnostics compile(String body) throws Exception {
		File specFile = createTempFile("diagnostic_fixture", ".slaspec");
		File slaFile = createTempFile("diagnostic_fixture", ".sla");
		FileUtilities.writeStringToFile(specFile, PREAMBLE + body);

		SleighCompile compiler = new SleighCompile();
		compiler.setAllOptions(Map.of(), false, true, false, false, false, false, false, true,
			false);

		logger.clear();
		ByteArrayOutputStream strayErrors = new ByteArrayOutputStream();
		PrintStream savedErr = System.err;
		int returnCode;
		try {
			System.setErr(new PrintStream(strayErrors, true, StandardCharsets.UTF_8));
			returnCode = compiler.run_compilation(specFile.getPath(), slaFile.getPath());
		}
		finally {
			System.setErr(savedErr);
		}

		List<String> errors = new ArrayList<>(logger.errors);
		strayErrors.toString(StandardCharsets.UTF_8)
				.lines()
				.filter(line -> !line.isBlank())
				.forEach(errors::add);
		return new Diagnostics(returnCode, errors, List.copyOf(logger.warnings));
	}

	/**
	 * Asserts that the compile failed and that some <em>error</em> contains all of {@code required},
	 * ignoring case and order. Failure prints everything reported, since the usual cause is a
	 * different diagnostic firing than the one intended.
	 */
	protected void assertError(Diagnostics diagnostics, String... required) {
		assertNotEquals("expected the compile to fail: " + diagnostics, 0,
			diagnostics.returnCode());
		for (String message : diagnostics.errors()) {
			if (StringUtilities.containsAllIgnoreCase(message, required)) {
				return;
			}
		}
		fail("No error contained all of " + Arrays.toString(required) + "\nGot: " + diagnostics);
	}

	/**
	 * The control. Establishes that {@link #PREAMBLE} is valid sleigh and that a good spec produces
	 * no errors -- without which every negative test below is worthless, since a fixture broken for
	 * some unrelated reason would still produce "an error".
	 */
	@Test
	public void testValidSpecCompilesWithoutError() throws Exception {
		Diagnostics diagnostics = compile("""
				:inc is op8=0x00 { r1 = r1 + 1; }
				:dec is op8=0x01 { r1 = r1 - 1; }
				""");

		assertEquals("valid spec should compile: " + diagnostics, 0, diagnostics.returnCode());
		assertTrue("valid spec should report no errors: " + diagnostics,
			diagnostics.errors().isEmpty());
	}

	/**
	 * A size mismatch between the inputs of a binary operator. Today the message names the table,
	 * the line and the operator, which is what this pins down; it does not name the conflicting
	 * sizes, which is what makes the common case hard to act on.
	 */
	@Test
	public void testSizeRestrictionNamesOperatorAndTable() throws Exception {
		Diagnostics diagnostics = compile("""
				:bad is op8=0x02 { r0 = r0 + oddSized; }
				""");

		assertError(diagnostics, "size restriction", "instruction", "Addition");
	}

	/**
	 * A varnode whose size cannot be inferred -- here because {@code zext} of a bare constant
	 * constrains nothing. The message must reach the offending statement, not just the constructor:
	 * the fixture puts the constructor on line 9 and the {@code zext} on line 11 precisely so that
	 * a message pointing at the constructor cannot pass this test.
	 */
	@Test
	public void testUnresolvedSizeNamesTheOperandAndStatement() throws Exception {
		Diagnostics diagnostics = compile("""
				:bad is op8=0x03 {
					r0 = r0 + 1;
					r1 = zext(1);
				}
				""");

		assertError(diagnostics, "could not resolve", "input 0", "zext", ":11");
	}

	/**
	 * Fields from two differently-sized tokens combined with {@code &}. Both tokens must be named:
	 * "mismatched tokens" alone does not say which two disagreed, and a real spec declares many.
	 */
	@Test
	public void testMismatchedTokensNamesBothTokens() throws Exception {
		Diagnostics diagnostics = compile("""
				:bad is op8=0x05 & op16=0x0605 { }
				""");

		assertError(diagnostics, "mismatched tokens", "instruction", "byteTok", "wordTok");
	}

	/**
	 * A pattern whose length is not fixed, where a fixed length is required. Which side carries the
	 * ellipsis is the actionable part, so the message must distinguish the two sides rather than
	 * just stating that the size varies.
	 */
	@Test
	public void testVaryingPatternSizeIdentifiesTheSideMissingTheEllipsis() throws Exception {
		Diagnostics diagnostics = compile("""
				:bad is op8=0x06 ... & op16=0x4342 { }
				""");

		assertError(diagnostics, "pattern size cannot vary", "instruction", "left", "right");
	}

	/**
	 * Truncation applied to a parenthesised expression. The grammar allows {@code :size} only on a
	 * variable or a constant, so this is a plain syntax error -- but "unexpected COLON" gives no
	 * hint that the fix is to assign the expression to an intermediate first.
	 */
	@Test
	public void testTruncationOnExpressionIsReported() throws Exception {
		Diagnostics diagnostics = compile("""
				:bad is op8=0x04 { r0 = (r0 + 1):2; }
				""");

		assertError(diagnostics, "unexpected COLON");
	}
}
