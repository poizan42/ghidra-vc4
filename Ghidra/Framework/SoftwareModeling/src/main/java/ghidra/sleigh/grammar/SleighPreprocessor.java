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
package ghidra.sleigh.grammar;

import java.io.*;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.antlr.runtime.*;
import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.config.Configurator;

import generic.stl.Pair;
import ghidra.pcodeCPort.slgh_compile.PreprocessorDefinitions;
import ghidra.util.Msg;
import utilities.util.FileResolutionResult;
import utilities.util.FileUtilities;

public class SleighPreprocessor implements ExpressionEnvironment {
	private static final Logger log = LogManager.getLogger(SleighPreprocessor.class);
	static {
		Configurator.setLevel(log.getName(), Level.INFO);
	}

	private static final Pattern INCLUDE = Pattern.compile("^\\s*@include\\s+\\\"(.*)\\\"\\s*$");
	private static final Pattern DEFINE1 =
		Pattern.compile("^\\s*@define\\s+([0-9A-Z_a-z]+)\\s+\\\"(.*)\\\"\\s*$");
	private static final Pattern DEFINE2 =
		Pattern.compile("^\\s*@define\\s+([0-9A-Z_a-z]+)\\s+(\\S+)\\s*$");
	private static final Pattern DEFINE3 = Pattern.compile("^\\s*@define\\s+([0-9A-Z_a-z]+)\\s*$");
	private static final Pattern UNDEF = Pattern.compile("^\\s*@undef\\s+([0-9A-Z_a-z]+)\\s*$");
	private static final Pattern IFDEF = Pattern.compile("^\\s*@ifdef\\s+([0-9A-Z_a-z]+)\\s*$");
	private static final Pattern IFNDEF = Pattern.compile("^\\s*@ifndef\\s+([0-9A-Z_a-z]+)\\s*$");
	private static final Pattern IF = Pattern.compile("^\\s*@if\\s+(.*)");
	private static final Pattern ELIF = Pattern.compile("^\\s*@elif\\s+(.*)");
	private static final Pattern ENDIF = Pattern.compile("^\\s*@endif\\s*$");
	// @repeat VAR FROM COUNT ... @endrepeat: emit the enclosed lines COUNT times with VAR bound to
	// FROM, FROM+1, ... Inside the body, `$(VAR)` is the loop value and `$[expr]` is folded to a
	// single integer literal. The folding is the whole point: a SLEIGH bit-range position is one
	// integer TOKEN (SemanticParser.g), and nothing downstream constant-folds, so `VdRow[$(L)*32,8]`
	// would not parse -- `VdRow[$[L*32],8]` does.
	private static final Pattern REPEAT =
		Pattern.compile("^\\s*@repeat\\s+([0-9A-Z_a-z]+)\\s+(-?[0-9]+)\\s+([0-9]+)\\s*$");
	private static final Pattern ENDREPEAT = Pattern.compile("^\\s*@endrepeat\\s*$");
	private static final Pattern ARITH = Pattern.compile("\\$\\[([^\\]]*)\\]");
	private static final Pattern ELSE = Pattern.compile("^\\s*@else\\s*$");

	private final PreprocessorDefinitions definitions;
	private boolean compatible = false;

	BooleanExpressionLexer lexer = null;
	BooleanExpressionParser parser = null;

	ArrayList<ConditionalHelper> ifstack;
	SleighPreprocessor myParent = null;
	long myLatestTimestamp = 0;
	int errorCount = 0;

	public SleighPreprocessor(PreprocessorDefinitions definitions, File inputFile) {
		this.definitions = definitions;
		this.file = inputFile;
		updateLatestDate(inputFile);
	}

	SleighPreprocessor(SleighPreprocessor parent, File inputFile) {
		this.definitions = parent.definitions;
		this.compatible = parent.compatible;
		this.file = inputFile;
		this.myParent = parent;
		updateLatestDate(inputFile);
	}

	public void process(LineArrayListWriter writer) throws IOException, PreprocessorException,
			RecognitionException {
		processInternal(writer, 1);
	}

	public long scanForTimestamp() throws IOException, PreprocessorException, RecognitionException {
		processInternal(new FakeLineArrayListWriter(), 1);
		return myLatestTimestamp;
	}

	public void setCompatible(boolean compatible) {
		this.compatible = compatible;
	}

	public boolean isCompatible() {
		return compatible;
	}

	private void processInternal(LineArrayListWriter writer, int overallLine) throws IOException,
			PreprocessorException, RecognitionException {
		this.lineno = 1;
		this.overallLineno = overallLine;

		this.ifstack = new ArrayList<ConditionalHelper>();
		ifstack.add(new ConditionalHelper(false, false, false, true));

		FileInputStream fis = new FileInputStream(file);
		InputStreamReader isr = new InputStreamReader(fis, "ISO-8859-1");

		try (BufferedReader in = new BufferedReader(isr)) {

			outputPosition(writer);

			log.trace("enter SleighPreprocessor");

			while ((line = in.readLine()) != null) {
				log.trace("top of while, state: " + this.toString());
				log.trace("got line: " + line);

				String origLine = line;

				// remove confirmed full-line comments
				line = line.replaceFirst("^\\s*#.*", "");

				if (line.length() > 0 && line.charAt(0) == '@') {

					// remove any comments in preprocessor
					line = line.replaceFirst("#.*", "");

					Matcher m;
					if ((m = INCLUDE.matcher(line)).matches()) {
						if (isCopy()) {
							String includeFileName = handleVariables(m.group(1), true);
							boolean isAbsolute = false;
							if (includeFileName.startsWith("/")) {
								isAbsolute = true;
							}
							else if (includeFileName.startsWith("\\")) {
								isAbsolute = true;
							}
							else if (includeFileName.matches("^[a-zA-Z_0-9]+:.*")) {
								isAbsolute = true;
							}
							final File includeFile = isAbsolute ? new File(includeFileName)
									: new File(file.getParent(), includeFileName);
							FileResolutionResult result =
								FileUtilities.existsAndIsCaseDependent(includeFile);
							if (!result.isOk()) {
								throw new PreprocessorException(
									"included file \"" + includeFile + "\": " + result.getMessage(),
									file.getName(), lineno, overallLineno, line);
							}
							SleighPreprocessor preprocessor =
								new SleighPreprocessor(this, includeFile);
							preprocessor.processInternal(writer, overallLineno);
							// increment the position now because we already replaced the include
							lineno++;
							overallLineno++;
							outputPosition(writer);
							// the one directive we skip printing a blank line
							continue;
						}
					}
					else if ((m = DEFINE1.matcher(line)).matches()) {
						if (isCopy()) {
							define(m.group(1), m.group(2));
						}
					}
					else if ((m = DEFINE2.matcher(line)).matches()) {
						if (isCopy()) {
							define(m.group(1), m.group(2));
						}
					}
					else if ((m = DEFINE3.matcher(line)).matches()) {
						if (isCopy()) {
							define(m.group(1), "");
						}
					}
					else if ((m = UNDEF.matcher(line)).matches()) {
						if (isCopy()) {
							undefine(m.group(1));
						}
					}
					else if ((m = IFDEF.matcher(line)).matches()) {
						enterif();
						Pair<Boolean, String> pair = definitions.lookup(m.group(1));
						boolean containsKey = pair.first;
						if (!containsKey) {
							setCopy(false);
							log.trace("@ifdef " + m.group(1) + ": NO");
						}
						else {
							setHandled(true);
							log.trace("@ifdef " + m.group(1) + ": yes");
						}
					}
					else if ((m = IFNDEF.matcher(line)).matches()) {
						enterif();
						Pair<Boolean, String> pair = definitions.lookup(m.group(1));
						boolean containsKey = pair.first;
						if (containsKey) {
							setCopy(false);
							log.trace("@ifndef " + m.group(1) + ": NO");
						}
						else {
							setHandled(true);
							log.trace("@ifndef " + m.group(1) + ": yes");
						}
					}
					else if ((m = IF.matcher(line)).matches()) {
						enterif();
						log.trace("@if...");
						handleExpression(m.group(1));
					}
					else if ((m = ELIF.matcher(line)).matches()) {
						enterelif();
						log.trace("@elif...");
						handleExpression(m.group(1));
					}
					else if ((m = ENDIF.matcher(line)).matches()) {
						leaveif();
						log.trace("@endif");
					}
					else if ((m = ELSE.matcher(line)).matches()) {
						enterelse();
						setCopy(!isHandled());
						log.trace("@else");
					}
					else if ((m = REPEAT.matcher(line)).matches()) {
						if (repeatBody != null) {
							throw new PreprocessorException("nested @repeat", file.getName(),
								lineno, overallLineno, line);
						}
						if (isCopy()) {
							repeatVar = m.group(1);
							repeatFrom = Integer.parseInt(m.group(2));
							repeatCount = Integer.parseInt(m.group(3));
							repeatBody = new ArrayList<String>();
						}
					}
					else if ((m = ENDREPEAT.matcher(line)).matches()) {
						if (repeatBody == null) {
							throw new PreprocessorException("@endrepeat outside @repeat",
								file.getName(), lineno, overallLineno, line);
						}
						ArrayList<String> body = repeatBody;
						repeatBody = null;
						for (int i = 0; i < repeatCount; i++) {
							for (String raw : body) {
								writer.write(handleVariables(
									bindRepeat(raw, repeatVar, repeatFrom + i), compatible));
								writer.newLine();
							}
						}
						// The output is now longer than the input, so resync the position stream the
						// same way the @include branch does -- otherwise every error after this point
						// reports a line number short by (COUNT-1) x body.
						writer.write("#" + origLine);
						writer.newLine();
						lineno++;
						overallLineno++;
						outputPosition(writer);
						continue;
					}
					else {
						throw new PreprocessorException("unrecognized preprocessor directive",
							file.getName(), lineno, overallLineno, line);
					}
					log.trace("PRINT " + lineno() + ": commenting directive out");
					writer.write("#" + origLine);
					writer.newLine();
				}
				else if (repeatBody != null) {
					// Buffered RAW: `$(VAR)` must not go through handleVariables yet, which would
					// reject the loop variable as an unknown @define.
					if (isCopy()) {
						repeatBody.add(line);
					}
				}
				else {
					if (isCopy()) {
						log.trace("PRINT " + lineno() + ": printing text");
						writer.write(handleVariables(line, compatible));
						writer.newLine();
					}
					else {
						log.trace(
							"PRINT " + lineno() + ": replacing text with non-copied blank line");
						writer.write("#" + line);
						writer.newLine();
					}
				}
				lineno++;
				overallLineno++;
			}
		}
		writer.flush();
		if (errorCount > 0) {
			throw new PreprocessorException("Errors during preprocessing", file.getName(), overallLine, 0, "");
		}
		log.trace("leave SleighPreprocessor");
	}

	void updateLatestDate(File possibleNewDateFile) {
		if (possibleNewDateFile != null && possibleNewDateFile.exists()) {
			long lastModified = possibleNewDateFile.lastModified();
			if (lastModified > myLatestTimestamp) {
				myLatestTimestamp = lastModified;
			}
			if (myParent != null) {
				myParent.updateLatestDate(possibleNewDateFile);
			}
		}
	}

	/** Bind the loop variable in one buffered line: `$(VAR)` to its value, `$[expr]` folded. */
	private String bindRepeat(String raw, String var, int value) throws PreprocessorException {
		String out = raw.replace("$(" + var + ")", Integer.toString(value));
		Matcher m;
		while ((m = ARITH.matcher(out)).find()) {
			String expr = m.group(1).replaceAll("\\b" + Pattern.quote(var) + "\\b",
				Integer.toString(value));
			out = out.substring(0, m.start()) + Long.toString(evalArith(expr, out)) +
				out.substring(m.end());
		}
		return out;
	}

	/** Integer + - * / % with parentheses. Deliberately tiny: the generator emits these. */
	private long evalArith(String expr, String context) throws PreprocessorException {
		int[] pos = { 0 };
		long v = arithSum(expr, pos, context);
		skipWs(expr, pos);
		if (pos[0] != expr.length()) {
			throw new PreprocessorException("trailing junk in $[" + expr + "]", file.getName(),
				lineno, overallLineno, context);
		}
		return v;
	}

	private void skipWs(String e, int[] p) {
		while (p[0] < e.length() && Character.isWhitespace(e.charAt(p[0]))) {
			p[0]++;
		}
	}

	private long arithSum(String e, int[] p, String ctx) throws PreprocessorException {
		long v = arithTerm(e, p, ctx);
		while (true) {
			skipWs(e, p);
			if (p[0] < e.length() && (e.charAt(p[0]) == '+' || e.charAt(p[0]) == '-')) {
				char op = e.charAt(p[0]++);
				long r = arithTerm(e, p, ctx);
				v = op == '+' ? v + r : v - r;
			}
			else {
				return v;
			}
		}
	}

	private long arithTerm(String e, int[] p, String ctx) throws PreprocessorException {
		long v = arithAtom(e, p, ctx);
		while (true) {
			skipWs(e, p);
			if (p[0] < e.length() &&
				(e.charAt(p[0]) == '*' || e.charAt(p[0]) == '/' || e.charAt(p[0]) == '%')) {
				char op = e.charAt(p[0]++);
				long r = arithAtom(e, p, ctx);
				if (op != '*' && r == 0) {
					throw new PreprocessorException("division by zero in $[" + e + "]",
						file.getName(), lineno, overallLineno, ctx);
				}
				v = op == '*' ? v * r : op == '/' ? v / r : v % r;
			}
			else {
				return v;
			}
		}
	}

	private long arithAtom(String e, int[] p, String ctx) throws PreprocessorException {
		skipWs(e, p);
		if (p[0] < e.length() && e.charAt(p[0]) == '(') {
			p[0]++;
			long v = arithSum(e, p, ctx);
			skipWs(e, p);
			if (p[0] >= e.length() || e.charAt(p[0]) != ')') {
				throw new PreprocessorException("unbalanced ( in $[" + e + "]", file.getName(),
					lineno, overallLineno, ctx);
			}
			p[0]++;
			return v;
		}
		if (p[0] < e.length() && e.charAt(p[0]) == '-') {
			p[0]++;
			return -arithAtom(e, p, ctx);
		}
		int st = p[0];
		if (p[0] + 1 < e.length() && e.charAt(p[0]) == '0' &&
			(e.charAt(p[0] + 1) == 'x' || e.charAt(p[0] + 1) == 'X')) {
			p[0] += 2;
			int hs = p[0];
			while (p[0] < e.length() && Character.digit(e.charAt(p[0]), 16) >= 0) {
				p[0]++;
			}
			if (p[0] == hs) {
				throw new PreprocessorException("bad hex in $[" + e + "]", file.getName(), lineno,
					overallLineno, ctx);
			}
			return Long.parseLong(e.substring(hs, p[0]), 16);
		}
		while (p[0] < e.length() && Character.isDigit(e.charAt(p[0]))) {
			p[0]++;
		}
		if (p[0] == st) {
			throw new PreprocessorException("expected a number in $[" + e + "]", file.getName(),
				lineno, overallLineno, ctx);
		}
		return Long.parseLong(e.substring(st, p[0]));
	}

	private String lineno() {
		return file.getName() + ":" + lineno + "(" + overallLineno + ")";
	}

	private void outputPosition(LineArrayListWriter out) throws IOException {
		if (!compatible) {
			String position = "\b" + file.getName() + "###" + lineno + "\b";
			out.write(position);
		}
	}

	private final File file;
	private ArrayList<String> repeatBody;
	private String repeatVar;
	private int repeatFrom;
	private int repeatCount;
	private String line;
	private int lineno;
	private int overallLineno;

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("lineno:");
		sb.append(lineno);
		sb.append(" ");
		sb.append(ifstack);
		return sb.toString();
	}

	private void handleExpression(String expression) throws RecognitionException, IOException {
		initParser(new StringReader(expression));
		if (isHandled()) {
			setCopy(false);
			log.trace("already handled");
		}
		else if (!parser.expression()) {
			setCopy(false);
			log.trace("expression '" + expression + "' is FALSE");
		}
		else {
			setCopy(true);
			setHandled(true);
			log.trace("expression '" + expression + "' is true");
		}
	}

	private void initParser(Reader reader) throws IOException {
		CharStream charStream = new ANTLRReaderStream(reader);

		lexer = new BooleanExpressionLexer(charStream);
		CommonTokenStream tokenStream = new CommonTokenStream(lexer);
		parser = new BooleanExpressionParser(tokenStream);
		parser.env = this;
	}

	private void enterelse() throws PreprocessorException {
		if (!isInif()) {
			throw new PreprocessorException("else outside of IF* directive", file.getName(),
				lineno, overallLineno, line);
		}
		if (isSawelse()) {
			throw new PreprocessorException("duplicate else directive", file.getName(), lineno,
				overallLineno, line);
		}
		setSawelse(true);
	}

	private void enterelif() throws PreprocessorException {
		if (!isInif()) {
			throw new PreprocessorException("elif outside of IF* directive", file.getName(),
				lineno, overallLineno, line);
		}
		if (isSawelse()) {
			throw new PreprocessorException("already saw else directive", file.getName(), lineno,
				overallLineno, line);
		}
	}

	private void enterif() {
		push(new ConditionalHelper(true, false, false, isCopy()));
	}

	private void leaveif() throws PreprocessorException {
		if (!isInif()) {
			throw new PreprocessorException("not in IF* directive", file.getName(), lineno,
				overallLineno, line);
		}
		pop();
	}

	private void undefine(String key) {
		log.trace("@undef " + key);
		definitions.undefine(key);
	}

	private void define(String key, String value) {
		log.trace("@define " + key + " " + value);
		definitions.set(key, value);
	}

	private static final Pattern EXPANSION = Pattern.compile("(\\$\\(([0-9A-Z_a-z]+)\\))");

	private String handleVariables(String input, boolean beCompatible) throws PreprocessorException {
		log.trace("handling line '" + input + "'");
		Matcher m;
		StringBuilder sb = new StringBuilder();
		while ((m = EXPANSION.matcher(input)).find()) {
			log.trace("found expansion: " + m.group());
			String variable = m.group(2);
			Pair<Boolean, String> pair = definitions.lookup(variable);
			boolean containsKey = pair.first;
			if (!containsKey) {
				throw new PreprocessorException("unknown variable: " + variable, file.getName(),
					lineno, overallLineno, line);
			}
			sb.append(input.substring(0, m.start(1)));
			if (!beCompatible) {
				sb.append("\b");
				sb.append(m.group());
				sb.append("\b");
			}
			sb.append(pair.second);
			input = input.substring(m.end(1));
		}
		sb.append(input);
		return sb.toString();
	}

	@Override
	public boolean equals(String lhs, String rhs) {
		if (lhs == null || rhs == null) {
			return false;
		}
		return lhs.equals(rhs);
	}

	@Override
	public String lookup(String variable) {
		Pair<Boolean, String> pair = definitions.lookup(variable);
		if (pair.first) {
			return pair.second;
		}
		return null;
	}

	@Override
	public void reportError(String msg) {
		errorCount += 1;
		Location location = new Location(file.getName(),lineno);
		Msg.error(this, location + ": " + msg);
	}

	private void push(ConditionalHelper conditionalHelper) {
		ifstack.add(conditionalHelper);
	}

	private void pop() {
		ifstack.remove(ifstack.size() - 1);
	}

	private ConditionalHelper top() {
		return ifstack.get(ifstack.size() - 1);
	}

	private boolean isInif() {
		return top().isInif();
	}

	private void setSawelse(boolean sawelse) {
		top().setSawelse(sawelse);
	}

	private boolean isSawelse() {
		return top().isSawelse();
	}

	private void setHandled(boolean handled) {
		top().setHandled(handled);
	}

	private boolean isHandled() {
		return top().isHandled();
	}

	private void setCopy(boolean copy) {
		top().setCopy(copy);
	}

	private boolean isCopy() {
		for (int ii = ifstack.size() - 1; ii >= 0; --ii) {
			if (!ifstack.get(ii).isCopy()) {
				return false;
			}
		}
		return true;
	}
}
