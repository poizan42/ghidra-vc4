/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.util.Map;
import java.util.TreeMap;

public class Locator {
	private TreeMap<Integer, Location> map = new TreeMap<Integer, Location>();

	public void registerLocation(int expandedLineNo, Location realLocation) {
		map.put(expandedLineNo, realLocation);
	}

	public Location getLocation(int expandedLineNo) {
		// floorEntry, NOT headMap().size()/lastKey(). This runs once per LEXED TOKEN
		// (AbstractSleighLexer.emit), and TreeMap.NavigableSubMap.size() is O(n) -- it walks the
		// submap -- so the cost was O(tokens x registered positions). With the handful of positions a
		// normal spec registers that is invisible; a spec whose preprocessor resyncs the position
		// stream thousands of times (many @includes, or an expanding directive) goes quadratic. A
		// 12,461-marker spec took the compile from 70 seconds to over 20 minutes, all of it here.
		// floorEntry is O(log n) and returns exactly the same entry headMap().lastKey() did.
		Map.Entry<Integer, Location> entry = map.floorEntry(expandedLineNo);
		if (entry == null) {
			return null;
		}
		Location location = entry.getValue();
		int actualLineNumber = expandedLineNo - entry.getKey() + location.lineno;
		return new Location(location.filename, actualLineNumber);
	}
}
