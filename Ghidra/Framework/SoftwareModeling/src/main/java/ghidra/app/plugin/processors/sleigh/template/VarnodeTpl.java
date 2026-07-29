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
/*
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.template;

import static ghidra.pcode.utils.SlaFormat.*;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 *  Placeholder for what will resolve to a Varnode instance given
 *  a specific InstructionContext
 */
public class VarnodeTpl {
	private ConstTpl space;
	private ConstTpl offset;
	private ConstTpl size;

	protected VarnodeTpl() {
	}

	public VarnodeTpl(ConstTpl space, ConstTpl offset, ConstTpl size) {
		this.space = space;
		this.offset = offset;
		this.size = size;
	}

	public ConstTpl getSpace() {
		return space;
	}

	public ConstTpl getOffset() {
		return offset;
	}

	public ConstTpl getSize() {
		return size;
	}

	public boolean isDynamic(ParserWalker walker) {
		if (offset.getType() != ConstTpl.HANDLE) {
			return false;
		}
		// Technically we should probably check all three ConstTpls
		// for dynamic handles, but in all cases, if there is any
		// dynamic piece, then the offset is dynamic
		return (walker.getFixedHandle(offset.getHandleIndex()).offset_space != null);

	}

	public boolean isRelative() {
		return (offset.getType() == ConstTpl.J_RELATIVE);
	}

	/**
	 * Read one varnode template, which the file may carry either in full or as an index into the
	 * shared varnode table.
	 * <p>
	 * A reference RETURNS THE TABLE'S OWN INSTANCE rather than a copy, so a template used a thousand
	 * times occupies one object on the heap. That is safe because this class is immutable once
	 * decoded -- it has no setters, and everything constructor-specific is resolved at build time
	 * through {@link ghidra.app.plugin.processors.sleigh.ParserWalker}.
	 * <p>
	 * The two forms are told apart by an attribute rather than by a distinct element, which is what
	 * lets every {@code peekElement() != 0} operand loop in this package stay as it was.
	 *
	 * @param decoder is the stream
	 * @param table is the shared varnode table, empty if the file carries none
	 * @return the decoded template, possibly shared
	 * @throws DecoderException for errors in the encoding
	 */
	public static VarnodeTpl decodeVarnode(Decoder decoder, VarnodeTpl[] table)
			throws DecoderException {
		int el = decoder.openElement(ELEM_VARNODE_TPL);
		int attrib = decoder.getNextAttributeId();
		if (attrib == ATTRIB_INDEX.id()) {
			int index = (int) decoder.readUnsignedInteger();
			decoder.closeElement(el);
			if ((index < 0) || (index >= table.length)) {
				throw new DecoderException(
					"Varnode reference " + index + " but the .sla holds no such table entry");
			}
			return table[index];
		}
		decoder.rewindAttributes();
		VarnodeTpl res = new VarnodeTpl();
		res.space = new ConstTpl();
		res.space.decode(decoder);
		res.offset = new ConstTpl();
		res.offset.decode(decoder);
		res.size = new ConstTpl();
		res.size.decode(decoder);
		decoder.closeElement(el);
		return res;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(space);
		sb.append('[');
		sb.append(offset);
		sb.append(':');
		sb.append(size);
		sb.append(']');

		return sb.toString();
	}
}
