// Pattern-based Solidity analyzer.
// Real (simplified) static analysis — when the source changes, findings change.
// Models Slither's detector output schema.

(function () {
  const DETECTORS = [
    {
      id: 'tx-origin',
      check: 'tx-origin',
      title: 'Authentication using tx.origin',
      impact: 'High',
      confidence: 'Medium',
      detect(src, lines) {
        const out = [];
        lines.forEach((line, i) => {
          if (/\btx\.origin\b/.test(line) && !/\/\//.test(line.split('tx.origin')[0])) {
            out.push({ lines: [i + 1], location: 'line ' + (i + 1),
              description: 'Authentication uses `tx.origin` instead of `msg.sender`. A malicious contract can trick a privileged user into calling it, then invoke this function as the privileged caller.' });
          }
        });
        return out;
      }
    },
    {
      id: 'reentrancy-eth',
      check: 'reentrancy-eth',
      title: 'Reentrancy in external call before state update',
      impact: 'High',
      confidence: 'Medium',
      detect(src, lines) {
        const out = [];
        // Find functions
        const funcs = extractFunctions(lines);
        funcs.forEach(fn => {
          const bodyLines = lines.slice(fn.start, fn.end + 1);
          let callIdx = -1;
          let stateAfterCall = -1;
          for (let i = 0; i < bodyLines.length; i++) {
            const line = bodyLines[i];
            if (/\.call\s*\{[^}]*value\s*:/.test(line) || /\.call\.value\s*\(/.test(line)) {
              callIdx = i;
            } else if (callIdx >= 0 && /(balances|balanceOf|owner|admin)\s*\[[^\]]*\]\s*[-+]?=/.test(line)) {
              stateAfterCall = i;
              break;
            } else if (callIdx >= 0 && /[a-zA-Z_]+\s*[-+]=/.test(line) && !/\(/.test(line)) {
              stateAfterCall = i;
              break;
            }
          }
          if (callIdx >= 0 && stateAfterCall > callIdx) {
            const absLine = fn.start + callIdx + 1;
            out.push({
              lines: [absLine, fn.start + stateAfterCall + 1],
              location: fn.name + '()',
              description: `Reentrancy in ${fn.name}(): External call at line ${absLine} executes before state variable update at line ${fn.start + stateAfterCall + 1}. An attacker contract can re-enter before the state is settled.`
            });
          }
        });
        return out;
      }
    },
    {
      id: 'unchecked-send',
      check: 'unchecked-send',
      title: 'Unchecked return value of low-level send',
      impact: 'Medium',
      confidence: 'High',
      detect(src, lines) {
        const out = [];
        lines.forEach((line, i) => {
          const trimmed = line.trim();
          if (/\.send\s*\(/.test(line) && !/(\b(bool|require|assert|if)\b)/.test(trimmed)) {
            out.push({
              lines: [i + 1],
              location: 'line ' + (i + 1),
              description: '`.send()` return value is not checked. If the transfer fails, execution continues silently and value may be lost.'
            });
          }
        });
        return out;
      }
    },
    {
      id: 'unchecked-lowlevel',
      check: 'unchecked-lowlevel',
      title: 'Unchecked return value of low-level call',
      impact: 'Medium',
      confidence: 'Medium',
      detect(src, lines) {
        const out = [];
        lines.forEach((line, i) => {
          if (/\.call\s*\(/.test(line) || /\.call\s*\{/.test(line)) {
            // If line uses pattern `(bool ok, ) = ...call(...)` and a `require(ok)` follows within 3 lines, it's checked.
            const captureSucc = /\(\s*bool\s+(\w+)\s*,/.exec(line);
            if (!captureSucc) {
              if (!/^\s*(if|require|assert)\b/.test(line)) {
                out.push({
                  lines: [i + 1],
                  location: 'line ' + (i + 1),
                  description: 'Low-level `.call()` return value is not captured or checked.'
                });
              }
            } else {
              const okVar = captureSucc[1];
              const within = lines.slice(i + 1, i + 5).join(' ');
              if (!new RegExp('require\\s*\\(\\s*' + okVar + '\\b').test(within) &&
                  !new RegExp('if\\s*\\(\\s*!?' + okVar + '\\b').test(within)) {
                out.push({
                  lines: [i + 1],
                  location: 'line ' + (i + 1),
                  description: '`.call()` succeeds variable `' + okVar + '` is not checked with `require` or `if`.'
                });
              }
            }
          }
        });
        return out;
      }
    },
    {
      id: 'missing-access-control',
      check: 'missing-access-control',
      title: 'Privileged state mutation without access control',
      impact: 'Critical',
      confidence: 'High',
      detect(src, lines) {
        const out = [];
        const funcs = extractFunctions(lines);
        funcs.forEach(fn => {
          const sigLine = lines[(fn.signatureLine || fn.start) - 1] || '';
          if (fn.name === 'constructor') return;
          const hasModifier = /\b(onlyOwner|onlyAdmin|onlyRole|auth|whenNotPaused|nonReentrant)\b/.test(sigLine);
          const body = lines.slice(fn.start, fn.end + 1).join('\n');
          const hasRequire = /require\s*\(\s*msg\.sender\s*==\s*(owner|admin|deployer|controller)/.test(body) ||
                             /if\s*\(\s*msg\.sender\s*!=/.test(body);
          const mutatesPrivileged = /^\s*(owner|admin|controller|paused)\s*=/.test(body) ||
                                    /^\s*(owner|admin|controller|paused)\s*=/m.test(body);
          // also: selfdestruct, mint operations, withdraw to anywhere
          const privilegedOp = /\b(selfdestruct|suicide)\s*\(/.test(body);
          if ((mutatesPrivileged || privilegedOp) && !hasModifier && !hasRequire) {
            // find offending line
            let offLine = fn.start + 1;
            for (let j = fn.start; j <= fn.end; j++) {
              if (/^\s*(owner|admin|controller|paused)\s*=/.test(lines[j]) ||
                  /\b(selfdestruct|suicide)\s*\(/.test(lines[j])) {
                offLine = j + 1; break;
              }
            }
            out.push({
              lines: [offLine],
              location: fn.name + '(...)',
              description: `Function \`${fn.name}\` modifies privileged state (e.g. \`owner\`/\`admin\`) without any access control — any caller can elevate privileges.`
            });
          }
        });
        return out;
      }
    },
    {
      id: 'timestamp',
      check: 'timestamp',
      title: 'Dangerous use of block.timestamp',
      impact: 'Low',
      confidence: 'Medium',
      detect(src, lines) {
        const out = [];
        lines.forEach((line, i) => {
          if ((/\bblock\.timestamp\b/.test(line) || /\bnow\b/.test(line)) &&
              /(require|if|while|<|>|<=|>=)/.test(line)) {
            out.push({
              lines: [i + 1],
              location: 'line ' + (i + 1),
              description: 'Uses `block.timestamp` in a comparison. Miners can manipulate block timestamps by up to ~15 seconds — risky if the comparison gates value.'
            });
          }
        });
        return out;
      }
    },
    {
      id: 'integer-overflow',
      check: 'integer-overflow',
      title: 'Unchecked arithmetic (no SafeMath, Solidity <0.8)',
      impact: 'High',
      confidence: 'High',
      detect(src, lines) {
        const out = [];
        const pragmaMatch = src.match(/pragma\s+solidity\s+([^;]+);/);
        if (!pragmaMatch) return out;
        const v = pragmaMatch[1];
        const oldSolc = /\^0\.[0-7]\b/.test(v) || /0\.[0-7]\./.test(v);
        if (!oldSolc) return out;
        // Look for unchecked ops
        lines.forEach((line, i) => {
          if (/^\s*[A-Za-z_$][\w$]*(?:\s*\[[^;=]*\]|\.[A-Za-z_$][\w$]*)*\s*[+\-*\/]=/.test(line) && !/using\s+SafeMath\s+for/.test(src)) {
            if (!/\/\//.test(line.split(/[+\-*\/]=/)[0])) {
              out.push({
                lines: [i + 1],
                location: 'line ' + (i + 1),
                description: 'Arithmetic without SafeMath on Solidity ' + v.trim() + ' — overflow/underflow is silent and exploitable.'
              });
            }
          }
        });
        return out;
      }
    },
    {
      id: 'missing-zero-check',
      check: 'missing-zero-check',
      title: 'Missing zero-address validation',
      impact: 'Low',
      confidence: 'Medium',
      detect(src, lines) {
        const out = [];
        const funcs = extractFunctions(lines);
        funcs.forEach(fn => {
          const sigLine = lines[(fn.signatureLine || fn.start) - 1] || '';
          const addrMatch = sigLine.match(/address(?:\s+(?:memory|calldata|payable))?\s+(\w+)/);
          if (!addrMatch) return;
          if (/transferOwnership|set\w+|init/.test(fn.name) || /^transfer$/.test(fn.name) || /^mint$/.test(fn.name)) {
            const param = addrMatch[1];
            const body = lines.slice(fn.start, fn.end + 1).join('\n');
            const hasCheck = new RegExp('require\\s*\\(\\s*' + param + '\\s*!=\\s*address\\s*\\(\\s*0').test(body) ||
                             new RegExp(param + '\\s*!=\\s*address\\s*\\(\\s*0').test(body);
            if (!hasCheck) {
              out.push({
                lines: [fn.signatureLine || fn.start],
                location: fn.name + '(' + param + ')',
                description: `\`${fn.name}\` does not validate that \`${param}\` is non-zero. Calling with the zero address may permanently lock state or burn value.`
              });
            }
          }
        });
        return out;
      }
    },
    {
      id: 'locked-ether',
      check: 'locked-ether',
      title: 'Transfer can lock contract state',
      impact: 'Medium',
      confidence: 'Medium',
      detect(src, lines) {
        const out = [];
        lines.forEach((line, i) => {
          if (/payable\s*\([^)]+\)\.transfer\s*\(/.test(line) || /\.transfer\s*\(\s*\w+\s*\)\s*;/.test(line)) {
            // payable(x).transfer(y) — fixed 2300 gas; revert on contract recipient with non-trivial fallback
            if (!/(\bowner\b|\bbeneficiary\b)/.test(line)) return; // be conservative
            out.push({
              lines: [i + 1],
              location: 'line ' + (i + 1),
              description: '`.transfer()` forwards a fixed 2300 gas. If the recipient is a contract whose fallback consumes more, the call reverts — potentially locking funds in this contract.'
            });
          }
        });
        return out;
      }
    },
    {
      id: 'suicidal',
      check: 'suicidal',
      title: 'Unprotected selfdestruct',
      impact: 'Critical',
      confidence: 'High',
      detect(src, lines) {
        const out = [];
        const funcs = extractFunctions(lines);
        funcs.forEach(fn => {
          const sigLine = lines[(fn.signatureLine || fn.start) - 1] || '';
          const body = lines.slice(fn.start, fn.end + 1).join('\n');
          if (/\b(selfdestruct|suicide)\s*\(/.test(body)) {
            const hasGuard = /\bonly\w+\b/.test(sigLine) ||
                             /require\s*\(\s*msg\.sender\s*==/.test(body);
            if (!hasGuard) {
              let lineNo = fn.start;
              for (let j = fn.start; j <= fn.end; j++) {
                if (/\b(selfdestruct|suicide)\s*\(/.test(lines[j])) { lineNo = j + 1; break; }
              }
              out.push({
                lines: [lineNo],
                location: fn.name + '()',
                description: 'Function calls `selfdestruct` without access control. Any caller can permanently destroy this contract.'
              });
            }
          }
        });
        return out;
      }
    },
    {
      id: 'low-level-calls',
      check: 'low-level-calls',
      title: 'Use of low-level call',
      impact: 'Informational',
      confidence: 'High',
      detect(src, lines) {
        const out = [];
        lines.forEach((line, i) => {
          if (/\.call\s*\{|\.call\s*\(|\.delegatecall|\.staticcall/.test(line)) {
            out.push({
              lines: [i + 1],
              location: 'line ' + (i + 1),
              description: 'Low-level call bypasses Solidity\'s type checks. Use only when variable gas forwarding is required and the target is trusted.'
            });
          }
        });
        return out.slice(0, 1); // de-dup, report once
      }
    },
    {
      id: 'solc-version',
      check: 'solc-version',
      title: 'Outdated Solidity pragma',
      impact: 'Informational',
      confidence: 'High',
      detect(src, lines) {
        const pragmaMatch = src.match(/pragma\s+solidity\s+([^;]+);/);
        if (!pragmaMatch) return [];
        const v = pragmaMatch[1];
        if (/\^0\.[0-7]\b|0\.[0-4]\./.test(v)) {
          const lineIdx = lines.findIndex(l => /pragma\s+solidity/.test(l));
          return [{
            lines: [lineIdx + 1],
            location: 'pragma',
            description: 'Pragma allows compiler ' + v.trim() + '. Older compilers contain known bugs and lack overflow checking. Pin to 0.8.20 or later.'
          }];
        }
        return [];
      }
    },
  ];

  // Crude function extractor — finds `function NAME(...)` blocks by counting braces.
  function extractFunctions(lines) {
    const funcs = [];
    const re = /^\s*(?:function\s+(\w+)|(constructor)|(receive)\s*\(|(fallback)\s*\()/;
    for (let i = 0; i < lines.length; i++) {
      const m = re.exec(lines[i]);
      if (!m) continue;
      const name = m[1] || m[2] || m[3] || m[4];
      // find the opening { (may be on same or next line)
      let braceLine = i;
      let depth = 0;
      let started = false;
      let start = -1, end = -1;
      for (let j = i; j < lines.length; j++) {
        const opens = (lines[j].match(/\{/g) || []).length;
        const closes = (lines[j].match(/\}/g) || []).length;
        depth += opens - closes;
        if (opens > 0 && !started) { started = true; start = j + 1; }
        if (started && depth <= 0) { end = j; break; }
      }
      if (start > 0 && end > 0) funcs.push({ name, start, end, signatureLine: i + 1 });
    }
    return funcs;
  }

  function analyze(source) {
    const lines = source.split('\n');
    const results = [];
    let n = 1;
    DETECTORS.forEach(det => {
      const found = det.detect(source, lines);
      found.forEach(f => {
        results.push({
          id: det.id + '-' + (n++),
          check: det.check,
          title: det.title,
          impact: det.impact,
          confidence: det.confidence,
          ...f
        });
      });
    });
    // sort by severity desc, line asc
    const rank = { Critical: 4, High: 3, Medium: 2, Low: 1, Informational: 0 };
    results.sort((a, b) => {
      const r = (rank[b.impact] || 0) - (rank[a.impact] || 0);
      if (r) return r;
      return (a.lines[0] || 0) - (b.lines[0] || 0);
    });
    return results;
  }

  window.SolidityAnalyzer = {
    analyze,
    detectors: DETECTORS.map(d => d.check),
  };
})();
