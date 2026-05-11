// Live Solidity editor — textarea over a syntax-highlighted overlay.
// Same padding + font + line-height on both layers ensures character alignment.

const { useRef, useMemo } = React;

function SolidityEditor({ value, onChange, findings = [], readOnly = false }) {
  const taRef = useRef(null);
  const preRef = useRef(null);

  // line → severity map
  const flagged = useMemo(() => {
    const map = {};
    const rank = { Critical: 4, High: 3, Medium: 2, Low: 1, Informational: 0 };
    findings.forEach(f => {
      f.lines.forEach(ln => {
        if (!map[ln] || (rank[f.impact] || 0) > (rank[map[ln]] || 0)) map[ln] = f.impact;
      });
    });
    return map;
  }, [findings]);

  const lines = value.split('\n');

  function handleScroll(e) {
    if (preRef.current) {
      preRef.current.scrollTop = e.target.scrollTop;
      preRef.current.scrollLeft = e.target.scrollLeft;
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Tab') {
      e.preventDefault();
      const ta = e.target;
      const s = ta.selectionStart, en = ta.selectionEnd;
      const newVal = value.substring(0, s) + '    ' + value.substring(en);
      onChange(newVal);
      requestAnimationFrame(() => { ta.selectionStart = ta.selectionEnd = s + 4; });
    }
  }

  return (
    <div className="editor-area">
      <div className="editor-pane">
        <pre ref={preRef} className="editor-pre" aria-hidden="true">
          {lines.map((line, i) => {
            const sev = flagged[i + 1];
            const tokens = window.tokenizeLine ? window.tokenizeLine(line) : [{ t: 'plain', v: line }];
            return (
              <div key={i} className={`code-line ${sev ? 'flagged' : ''}`} data-sev={sev || ''}>
                <span className="gutter-num">{i + 1}</span>
                <span className="line-code">
                  {tokens.map((t, j) =>
                    t.t === 'plain'
                      ? <React.Fragment key={j}>{t.v}</React.Fragment>
                      : <span key={j} className={`tok-${t.t}`}>{t.v}</span>
                  )}
                  {line.length === 0 ? ' ' : ''}
                </span>
              </div>
            );
          })}
        </pre>
        <textarea
          ref={taRef}
          className="editor-textarea"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onScroll={handleScroll}
          onKeyDown={handleKeyDown}
          spellCheck={false}
          readOnly={readOnly}
          autoCorrect="off"
          autoCapitalize="off"
        />
      </div>
    </div>
  );
}

window.SolidityEditor = SolidityEditor;
