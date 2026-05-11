// Audit report — editorial print-publication layout.

function severityRank(s) {
  return ({ Critical: 4, High: 3, Medium: 2, Low: 1, Informational: 0 })[s] ?? 0;
}
function overallRisk(findings) {
  if (findings.length === 0) return 'Clean';
  const max = Math.max(...findings.map(f => severityRank(f.impact)));
  return ['Clean', 'Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'][max];
}
function riskClass(label) {
  return ({
    'Critical Risk': 'crit',
    'High Risk': 'high',
    'Medium Risk': 'med',
    'Low Risk': 'low',
    'Clean': 'ok',
  })[label] || '';
}
function riskColor(label) {
  return ({
    'Critical Risk': 'var(--crit)',
    'High Risk': 'var(--high)',
    'Medium Risk': 'var(--med)',
    'Low Risk': 'var(--low)',
    'Clean': 'var(--ok)',
  })[label] || 'var(--ink)';
}
function countBySev(findings) {
  const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  findings.forEach(f => { c[f.impact] = (c[f.impact] || 0) + 1; });
  return c;
}

// Diff-style fix code renderer
function FixDiff({ code }) {
  const lines = (code || '').split('\n');
  return (
    <pre className="fix-code">
      {lines.map((line, i) => {
        const add = line.startsWith('+ ');
        const rem = line.startsWith('- ');
        const stripped = add || rem ? line.slice(2) : line;
        const toks = window.tokenizeLine ? window.tokenizeLine(stripped) : [{ t: 'plain', v: stripped }];
        return (
          <div key={i} className={`fix-line ${add ? 'add' : rem ? 'rem' : ''}`}>
            <span className="marker">{add ? '+' : rem ? '−' : ' '}</span>
            {toks.map((t, j) => t.t === 'plain'
              ? <React.Fragment key={j}>{t.v}</React.Fragment>
              : <span key={j} className={`tok-${t.t}`}>{t.v}</span>
            )}
          </div>
        );
      })}
    </pre>
  );
}

function ReportView({ contract, findings, results, onBack }) {
  const sorted = [...findings].sort((a, b) => severityRank(b.impact) - severityRank(a.impact));
  const counts = countBySev(findings);
  const risk = overallRisk(findings);
  const auditId = React.useMemo(() => 'AAI-' + Math.floor(Math.random() * 90000 + 10000), []);
  const dateStr = React.useMemo(() => new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }), []);

  function downloadPDF() { window.print(); }

  return (
    <div className="fade-in">
      <div className="crumbs">
        <button onClick={onBack}>◂ New audit</button>
        <span className="sep">/</span>
        <span>Report</span>
        <span className="sep">/</span>
        <span className="cur">{contract.name}</span>
      </div>

      <div className="report-masthead">
        <div>
          <div className="report-eyebrow">AuditAI · Security Audit Report</div>
          <h1 className="report-title">{contract.name.replace(/\.sol$/, '')} <span className="ital">audit</span></h1>
          <div className="report-byline">
            <span>Audit ID · {auditId}</span>
            <span className="div">·</span>
            <span>{dateStr}</span>
            <span className="div">·</span>
            <span>{contract.loc || contract.source.split('\n').length} LoC</span>
            <span className="div">·</span>
            <span>{findings.length} findings</span>
          </div>
        </div>
        <div className="verdict">
          <div className="verdict-kicker">Overall verdict</div>
          <div className="verdict-label" style={{ color: riskColor(risk) }}>{risk}</div>
        </div>
      </div>

      <div className="report-actions">
        <button className="btn btn-accent" onClick={downloadPDF}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Download as PDF
        </button>
        <button className="btn btn-ghost" onClick={onBack}>Audit another contract</button>
      </div>

      <div className="stats">
        <div className="stat crit"><div className="num">{counts.Critical}</div><div className="lbl">Critical</div></div>
        <div className="stat high"><div className="num">{counts.High}</div><div className="lbl">High</div></div>
        <div className="stat med"><div className="num">{counts.Medium}</div><div className="lbl">Medium</div></div>
        <div className="stat low"><div className="num">{counts.Low}</div><div className="lbl">Low</div></div>
        <div className="stat"><div className="num" style={{ color: 'var(--info)' }}>{counts.Informational}</div><div className="lbl">Informational</div></div>
      </div>

      {/* Executive summary — two column editorial layout */}
      <div className="body-grid">
        <div className="body-label">Executive<br/>Summary</div>
        <div className="body-prose">
          <p className="dropcap">
            AuditAI analyzed <strong>{contract.name}</strong> ({contract.loc || contract.source.split('\n').length} lines of Solidity) using Slither static analysis combined with claude-sonnet-4-5 reasoning across the SWC vulnerability taxonomy.
          </p>
          <p>
            The contract was rated <strong style={{ color: riskColor(risk) }}>{risk}</strong> with <strong>{findings.length}</strong> findings:{' '}
            {counts.Critical > 0 && <span><strong style={{ color: 'var(--crit)' }}>{counts.Critical} critical</strong>, </span>}
            {counts.High > 0 && <span><strong style={{ color: 'var(--high)' }}>{counts.High} high</strong>, </span>}
            {counts.Medium > 0 && <span><strong style={{ color: 'var(--med)' }}>{counts.Medium} medium</strong>, </span>}
            {(counts.Low + counts.Informational) > 0 && <span><strong style={{ color: 'var(--low)' }}>{counts.Low + counts.Informational} low/informational</strong></span>}
            . Each finding includes a plain-English explanation, a contextual exploit assessment, and a corrected code example.
          </p>
          {findings.length > 0 && (
            <p>
              <strong>This contract should not be deployed to production</strong> until all Critical and High severity findings are remediated and the contract is re-audited.
            </p>
          )}
          {findings.length === 0 && (
            <p>
              No vulnerabilities were detected by the configured static analyzers. This does not guarantee correctness — manual review, fuzzing, and formal verification are recommended for high-value deployments.
            </p>
          )}
        </div>
      </div>

      {/* Findings */}
      <div className="section-head" style={{ marginBottom: 0 }}>
        <span className="num">II</span>
        <div>
          <div className="title">Detailed findings</div>
        </div>
        <div className="sub">{findings.length} {findings.length === 1 ? 'finding' : 'findings'} · sorted by severity</div>
      </div>

      {findings.length === 0 && (
        <div style={{
          padding: '60px 20px',
          textAlign: 'center',
          fontFamily: 'Newsreader, serif',
          fontStyle: 'italic',
          color: 'var(--ink-dim)',
          fontSize: 20,
          borderBottom: '1px solid var(--rule)'
        }}>
          No vulnerabilities detected.
        </div>
      )}

      <div className="findings stagger">
        {sorted.map((f, idx) => {
          const r = results[f.id] || {};
          const fnLine = f.lines && f.lines.length > 1 ? `lines ${f.lines[0]}–${f.lines[f.lines.length-1]}` : `line ${f.lines[0]}`;
          return (
            <div key={f.id} className="finding" id={`finding-${idx + 1}`}>
              <div className="finding-head">
                <div className="finding-num">{String(idx + 1).padStart(2, '0')}</div>
                <div>
                  <h3 className="finding-title">{f.title}</h3>
                  <div className="finding-meta">
                    {contract.name} · {f.location} · {fnLine} · detector: <code>{f.check}</code> · confidence: {f.confidence}
                  </div>
                </div>
                <span className={`badge badge-${f.impact.toLowerCase()}`}>{f.impact}</span>
              </div>

              <div className="finding-grid">
                <div className="field-label">Slither<br/>detection</div>
                <div className="field-body field-row">{f.description}</div>

                <div className="field-label">
                  Explanation
                  <div className="ai-tag">— by AI</div>
                </div>
                <div className="field-body field-row">{r.explanation || '—'}</div>

                <div className="field-label">
                  Exploit<br/>scenario
                  <div className="ai-tag">— by AI</div>
                </div>
                <div className="field-body field-row">{r.danger || '—'}</div>

                <div className="field-label">
                  Recommended<br/>fix
                  <div className="ai-tag">— by AI</div>
                </div>
                <div className="field-body field-row">
                  <FixDiff code={r.fix || '// remediation pending'} />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

window.ReportView = ReportView;
