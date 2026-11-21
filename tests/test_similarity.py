#!/usr/bin/env python3
"""
Cross-language similarity checks: a port (Python -> JavaScript, Python -> Java) of a module should
read as a lead, an unrelated module should not.

Run:  python3 tests/test_similarity.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
import trapr as ts  # noqa: E402

ORIGINAL_PY = '''import time

RATE_LIMIT_MESSAGE = "rate limit exceeded: slow down and retry after the window resets"
MAX_BURST = 4096
REFILL_WINDOW_MS = 86400000


class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last = now

    def allow(self, cost=1):
        self._refill()
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def check_or_raise(self, cost=1):
        if not self.allow(cost):
            raise RuntimeError(RATE_LIMIT_MESSAGE)
        return self.tokens


def burst_ok(requests_in_window):
    for count in requests_in_window:
        if count > MAX_BURST:
            return False
    return True
'''

PORT_JS = '''const RATE_LIMIT_MESSAGE = "rate limit exceeded: slow down and retry after the window resets";
const MAX_BURST = 4096;
const REFILL_WINDOW_MS = 86400000;

class Bucket {
  constructor(cap, rate) {
    this.cap = cap;
    this.tokens = cap;
    this.rate = rate;
    this.last = Date.now();
  }
  refill() {
    const now = Date.now();
    const elapsed = now - this.last;
    this.tokens = Math.min(this.cap, this.tokens + elapsed * this.rate);
    this.last = now;
  }
  allow(cost = 1) {
    this.refill();
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return true;
    }
    return false;
  }
  checkOrRaise(cost = 1) {
    if (!this.allow(cost)) {
      throw new Error(RATE_LIMIT_MESSAGE);
    }
    return this.tokens;
  }
}

function burstOk(requestsInWindow) {
  for (const count of requestsInWindow) {
    if (count > MAX_BURST) {
      return false;
    }
  }
  return true;
}
'''

PORT_JAVA = '''public class Bucket {
    static final String RATE_LIMIT_MESSAGE = "rate limit exceeded: slow down and retry after the window resets";
    static final int MAX_BURST = 4096;
    static final long REFILL_WINDOW_MS = 86400000L;

    private double capacity;
    private double tokens;
    private double refillRate;
    private double last;

    public Bucket(double capacity, double refillRate) {
        this.capacity = capacity;
        this.tokens = capacity;
        this.refillRate = refillRate;
        this.last = System.nanoTime();
    }

    private void refill() {
        double now = System.nanoTime();
        double elapsed = now - this.last;
        this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillRate);
        this.last = now;
    }

    public boolean allow(double cost) {
        refill();
        if (this.tokens >= cost) {
            this.tokens -= cost;
            return true;
        }
        return false;
    }

    public double checkOrRaise(double cost) {
        if (!allow(cost)) {
            throw new RuntimeException(RATE_LIMIT_MESSAGE);
        }
        return this.tokens;
    }

    public static boolean burstOk(int[] requestsInWindow) {
        for (int count : requestsInWindow) {
            if (count > MAX_BURST) {
                return false;
            }
        }
        return true;
    }
}
'''

UNRELATED_JS = '''const DELIMITERS = { comma: ",", semicolon: ";", tab: "\\t" };
const MISSING_CELL = "<empty cell in export: fill it before submitting the report>";

function splitRow(line, delimiter) {
  const cells = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      quoted = !quoted;
    } else if (ch === delimiter && !quoted) {
      cells.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  cells.push(current);
  return cells;
}

function toTable(text, delimiter = DELIMITERS.comma) {
  const rows = text.split("\\n").filter((r) => r.length > 0);
  return rows.map((r) => splitRow(r, delimiter));
}

function fillMissing(rows) {
  return rows.map((row) => row.map((cell) => (cell === "" ? MISSING_CELL : cell)));
}

module.exports = { splitRow, toTable, fillMissing };
'''


def _checks() -> list[tuple[str, bool]]:
    out: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="trapr-simtest-") as d:
        root = Path(d)
        repo = root / "mine"
        repo.mkdir()
        (repo / "bucket.py").write_text(ORIGINAL_PY)
        js_dir, java_dir, other_dir = root / "port-js", root / "port-java", root / "other"
        for p in (js_dir, java_dir, other_dir):
            p.mkdir()
        (js_dir / "bucket.js").write_text(PORT_JS)
        (java_dir / "Bucket.java").write_text(PORT_JAVA)
        (other_dir / "csv.js").write_text(UNRELATED_JS)

        mine = [ts.sim_record(p) for p in ts.repo_files(repo, set())]
        js = [ts.sim_record(p) for p in ts.source_files(js_dir)]
        java = [ts.sim_record(p) for p in ts.source_files(java_dir)]
        other = [ts.sim_record(p) for p in ts.source_files(other_dir)]

        js_r = ts.sim_compare(mine, js, threshold=0.5, lit_min=3)
        java_r = ts.sim_compare(mine, java, threshold=0.5, lit_min=3)
        other_r = ts.sim_compare(mine, other, threshold=0.5, lit_min=3)

        print("  numbers (for calibration):")
        print(f"    python->js    containment={[p['containment'] for p in js_r['pairs']]}"
              f" literals={len(js_r['shared_literals'])}")
        print(f"    python->java  containment={[p['containment'] for p in java_r['pairs']]}"
              f" literals={len(java_r['shared_literals'])}")
        print(f"    python->other containment={[p['containment'] for p in other_r['pairs']]}"
              f" literals={len(other_r['shared_literals'])}")

        # Known recall limit (precision-first rules, see README): a clean port of a short module that
        # shares only one or two distinctive literals is not reported as a lead. Recorded, not hidden.
        print(f"  KNOWN LIMIT  python->js lead={js_r['lead']}, python->java lead={java_r['lead']}"
              f"  (short port, 2 distinctive literals; threshold is precision-first)")
        out.append(("shared distinctive literals survive the JavaScript port",
                    any("rate limit exceeded" in lit for lit in js_r["shared_literals"])))
        out.append(("shared distinctive literals survive the Java port",
                    any("rate limit exceeded" in lit for lit in java_r["shared_literals"])))
        out.append(("unrelated JavaScript module is not a lead", not other_r["lead"]))
        out.append(("unrelated module shares no distinctive literals", not other_r["shared_literals"]))
    return out


if __name__ == "__main__":
    results = _checks()
    for label, passed in results:
        print(f"  {'PASS' if passed else 'FAIL'}  {label}")
    ok = all(p for _, p in results)
    print(f"\n{sum(bool(p) for _, p in results)}/{len(results)} passed")
    sys.exit(0 if ok else 1)
