// Minimal Solidity syntax highlighter for the demo.
// Tokenizes lines into spans — comments, keywords, types, functions, strings.

const SOL_KEYWORDS = new Set([
  'pragma','solidity','contract','interface','library','function','modifier','event',
  'returns','return','public','private','internal','external','payable','view','pure',
  'memory','storage','calldata','constant','immutable','if','else','for','while','do',
  'break','continue','require','assert','revert','emit','new','delete','this','super',
  'using','is','as','from','import','virtual','override','abstract','constructor','receive','fallback',
  'try','catch','unchecked','assembly'
]);
const SOL_TYPES = new Set([
  'address','bool','string','bytes','byte','uint','int','mapping','true','false','wei','ether','gwei'
]);

// uint8..256, int8..256, bytes1..32
function isType(w) {
  if (SOL_TYPES.has(w)) return true;
  if (/^u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/.test(w)) return true;
  if (/^bytes([1-9]|[12][0-9]|3[0-2])?$/.test(w)) return true;
  return false;
}

function tokenizeLine(line) {
  // handle full-line comments quickly
  const trim = line.trimStart();
  if (trim.startsWith('//')) return [{ t: 'com', v: line }];

  // split out trailing // comment
  let codePart = line;
  let commentPart = '';
  const ci = (function findComment() {
    let inStr = null;
    for (let i = 0; i < line.length - 1; i++) {
      const c = line[i];
      if (inStr) {
        if (c === '\\') { i++; continue; }
        if (c === inStr) inStr = null;
      } else if (c === '"' || c === "'") {
        inStr = c;
      } else if (c === '/' && line[i+1] === '/') {
        return i;
      }
    }
    return -1;
  })();
  if (ci >= 0) { codePart = line.slice(0, ci); commentPart = line.slice(ci); }

  const tokens = [];
  const regex = /("(?:\\.|[^"\\])*")|('(?:\\.|[^'\\])*')|(\b\d+\b)|([A-Za-z_$][A-Za-z0-9_$]*)|(\s+)|([^\sA-Za-z0-9_$"']+)/g;
  let m, prevWord = null;
  while ((m = regex.exec(codePart)) !== null) {
    const [full, str1, str2, num, word, ws, sym] = m;
    if (str1 || str2) tokens.push({ t: 'str', v: full });
    else if (num) tokens.push({ t: 'num', v: full });
    else if (word) {
      if (SOL_KEYWORDS.has(word)) tokens.push({ t: 'key', v: word });
      else if (isType(word)) tokens.push({ t: 'type', v: word });
      else if (prevWord === 'function' || prevWord === 'modifier' || prevWord === 'event') tokens.push({ t: 'fn', v: word });
      else {
        // check if followed by '(' for function call coloring
        const after = codePart.slice(regex.lastIndex).match(/^\s*\(/);
        if (after) tokens.push({ t: 'fn', v: word });
        else tokens.push({ t: 'plain', v: word });
      }
      prevWord = word;
    }
    else if (ws) tokens.push({ t: 'plain', v: full });
    else if (sym) tokens.push({ t: 'plain', v: full });
  }
  if (commentPart) tokens.push({ t: 'com', v: commentPart });
  return tokens;
}

function renderTokens(tokens, key) {
  return tokens.map((tok, i) => {
    if (tok.t === 'plain') return tok.v;
    return <span key={i} className={`tok-${tok.t}`}>{tok.v}</span>;
  });
}

window.tokenizeLine = tokenizeLine;
window.renderTokens = renderTokens;

// Higher-level: code block component
function CodeBlock({ source, flaggedLines = {}, onLineClick }) {
  const lines = source.split('\n');
  return (
    <div className="code-body">
      <pre>
        {lines.map((line, idx) => {
          const ln = idx + 1;
          const sev = flaggedLines[ln];
          const cls = ['code-line'];
          if (sev) {
            cls.push('flag-line');
            if (sev === 'Critical') cls.push('crit');
            else if (sev === 'Medium') cls.push('med');
            else if (sev === 'Low' || sev === 'Informational') cls.push('low');
          }
          return (
            <div key={ln} className={cls.join(' ')} onClick={() => onLineClick && onLineClick(ln)}>
              <span className="ln">{ln}</span>
              <span>{renderTokens(tokenizeLine(line), ln)}</span>
            </div>
          );
        })}
      </pre>
    </div>
  );
}

// Fix code with simple highlighting + + line markers
function FixCode({ code }) {
  const lines = code.split('\n');
  return (
    <pre className="fix-code">
      {lines.map((line, idx) => {
        const isAdd = line.startsWith('+ ');
        const isRem = line.startsWith('- ');
        const stripped = isAdd || isRem ? line.slice(2) : line;
        const toks = tokenizeLine(stripped);
        return (
          <div key={idx} style={{
            color: isAdd ? '#86efac' : isRem ? '#fca5a5' : undefined,
            background: isAdd ? 'rgba(94,234,212,0.06)' : isRem ? 'rgba(239,68,68,0.06)' : undefined,
            padding: '0 4px',
            marginLeft: '-4px'
          }}>
            <span style={{ width: 14, display: 'inline-block', color: isAdd ? '#5eead4' : isRem ? '#fca5a5' : 'transparent' }}>
              {isAdd ? '+' : isRem ? '−' : ' '}
            </span>
            {renderTokens(toks, idx)}
          </div>
        );
      })}
    </pre>
  );
}

window.CodeBlock = CodeBlock;
window.FixCode = FixCode;
