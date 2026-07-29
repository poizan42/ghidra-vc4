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
package ghidra.pcodeCPort.sleighbase;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.AttributeId;
import ghidra.program.model.pcode.ElementId;
import ghidra.program.model.pcode.Encoder;

import static ghidra.pcode.utils.SlaFormat.*;

/**
 * The shared table of varnode templates written into a {@code .sla}, and the {@link Encoder} that
 * emits references to it.
 * <p>
 * A varnode template repeats enormously in a generated spec: the VideoCore vector spec writes
 * 1,383,725 of them and only 112,075 are distinct, because every constructor names the same registers,
 * lane offsets and sizes. Storing each distinct template once and referencing it by index cuts the
 * inflated stream by about 44%, which is also load time and heap since decode is fully eager.
 * <p>
 * <b>Why an {@code Encoder} wrapper rather than a parameter.</b> The path from {@code SleighBase.encode}
 * down to {@code VarnodeTpl.encode} crosses the polymorphic {@code SleighSymbol.encode(Encoder)}, which
 * has around eighteen overrides. Threading a table argument would touch all of them for no benefit.
 * Carrying it on the encoder instead means {@code VarnodeTpl.encode} is the only method that changes.
 * <p>
 * <b>Why a {@link TreeMap} and not a {@link java.util.HashMap}.</b> Neither {@code VarnodeTpl} nor
 * {@code ConstTpl} defines {@code hashCode}. A hash map would therefore fall back to identity hashing,
 * find no duplicates at all, and produce a table with one entry per use -- a *silent* failure that looks
 * like the feature working and saving nothing. {@code compareTo} exists and covers exactly the three
 * encoded fields, so an ordered map is both correct and cheap to reason about.
 */
public class VarnodeInterner implements Encoder {

	private final Encoder inner;
	private final Map<VarnodeTpl, Integer> index;
	private boolean interning = true;

	private VarnodeInterner(Encoder inner, Map<VarnodeTpl, Integer> index) {
		this.inner = inner;
		this.index = index;
	}

	/**
	 * Build the table from the templates collected by a pre-pass and write it out.
	 * <p>
	 * The table is written through the RAW encoder, not through this wrapper: an entry describes a
	 * varnode in full and must never become a reference to itself.
	 *
	 * @param encoder is the raw stream encoder
	 * @param counts maps each distinct template to the number of times it is used
	 * @return an encoder that emits references, or the raw encoder if there is nothing to intern
	 * @throws IOException for errors in the underlying stream
	 */
	public static Encoder writeTable(Encoder encoder, Map<VarnodeTpl, Integer> counts)
			throws IOException {
		if (counts.isEmpty()) {
			// Nothing to intern, so write no element at all -- a language with no repetition then
			// differs from the previous format only by the version, and the reader's peek finds
			// nothing, exactly as for the macro table.
			return encoder;
		}
		// Descending use count, so the hottest templates land on the indices that encode in the
		// fewest payload bytes. Ties broken by the template's own order so the output is
		// deterministic: two runs of the compiler must produce the same .sla.
		List<Map.Entry<VarnodeTpl, Integer>> byUse = new ArrayList<>(counts.entrySet());
		byUse.sort((a, b) -> {
			int c = Integer.compare(b.getValue(), a.getValue());
			return c != 0 ? c : a.getKey().compareTo(b.getKey());
		});
		Map<VarnodeTpl, Integer> index = new TreeMap<>(VarnodeTpl::compareTo);
		encoder.openElement(ELEM_VARNODE_TABLE);
		for (Map.Entry<VarnodeTpl, Integer> ent : byUse) {
			index.put(ent.getKey(), index.size());
			ent.getKey().encode(encoder);
		}
		encoder.closeElement(ELEM_VARNODE_TABLE);
		return new VarnodeInterner(encoder, index);
	}

	/**
	 * Write one varnode as a reference, if it is in the table.
	 *
	 * @param vn is the template to write
	 * @return true if a reference was written, false if the caller must encode it in full
	 * @throws IOException for errors in the underlying stream
	 */
	public boolean writeReference(VarnodeTpl vn) throws IOException {
		if (!interning) {
			return false;
		}
		Integer i = index.get(vn);
		if (i == null) {
			return false;
		}
		inner.openElement(ELEM_VARNODE_TPL);
		inner.writeUnsignedInteger(ATTRIB_INDEX, i);
		inner.closeElement(ELEM_VARNODE_TPL);
		return true;
	}

	/**
	 * @param encoder is any encoder
	 * @return the interner behind it, or null if references are not being emitted
	 */
	public static VarnodeInterner of(Encoder encoder) {
		return (encoder instanceof VarnodeInterner vi) ? vi : null;
	}

	@Override
	public void openElement(ElementId elemId) throws IOException {
		inner.openElement(elemId);
	}

	@Override
	public void closeElement(ElementId elemId) throws IOException {
		inner.closeElement(elemId);
	}

	@Override
	public void writeBool(AttributeId attribId, boolean val) throws IOException {
		inner.writeBool(attribId, val);
	}

	@Override
	public void writeSignedInteger(AttributeId attribId, long val) throws IOException {
		inner.writeSignedInteger(attribId, val);
	}

	@Override
	public void writeUnsignedInteger(AttributeId attribId, long val) throws IOException {
		inner.writeUnsignedInteger(attribId, val);
	}

	@Override
	public void writeString(AttributeId attribId, String val) throws IOException {
		inner.writeString(attribId, val);
	}

	@Override
	public void writeStringIndexed(AttributeId attribId, int idx, String val) throws IOException {
		inner.writeStringIndexed(attribId, idx, val);
	}

	@Override
	public void writeSpace(AttributeId attribId, AddressSpace spc) throws IOException {
		inner.writeSpace(attribId, spc);
	}

	@Override
	public void writeSpace(AttributeId attribId, int idx, String name) throws IOException {
		inner.writeSpace(attribId, idx, name);
	}

	@Override
	public void writeOpcode(AttributeId attribId, OpCode opcode) throws IOException {
		inner.writeOpcode(attribId, opcode);
	}

	@Override
	public void writeOpcode(AttributeId attribId, int opcode) throws IOException {
		inner.writeOpcode(attribId, opcode);
	}
}
