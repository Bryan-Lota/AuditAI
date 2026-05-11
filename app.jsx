// AuditAI — main app.
// Phases: select+edit → pipeline → report

const { useState, useEffect, useMemo } = React;

function Masthead() {
  const date = new Date().toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  return (
    <div className="masthead">
      <div className="masthead-inner">
        <div className="brand">Audit<span className="ital">AI</span></div>
        <div className="masthead-meta serif">{"\n"}</div>
        <div className="masthead-tools">
          <span className="item"><span className="status-dot" />claude-sonnet-4-5</span>
          <span className="item">Slither v0.10</span>
          <span className="item">SmartBugs · 47</span>
        </div>
      </div>
    </div>);

}

function Leader() {
  return (
    <div className="leader">
      <div>
        <div className="leader-eyebrow">AI-Powered Smart Contract Auditing</div>
        <h1 className="leader-title">
          Static analysis,<br />explained in <span className="em">plain English.</span>
        </h1>
        <p className="leader-deck serif">
          AuditAI combines Slither static analysis with claude-sonnet-4-5 reasoning to produce
          human-readable audit reports for Solidity smart contracts — bridging the gap between professional
          audits and raw tool output for the developer who builds real products but cannot access elite-tier
          security tooling.
        </p>
      </div>
      <div className="leader-divider" />
      <div className="leader-side">
        <h3>The five-layer pipeline</h3>
        <div className="side-line"><span className="k"><span className="serif ital">i.</span> Upload</span><span className="v">.sol file</span></div>
        <div className="side-line"><span className="k"><span className="serif ital">ii.</span> Static analysis</span><span className="v">Slither · 90+ detectors</span></div>
        <div className="side-line"><span className="k"><span className="serif ital">iii.</span> Extraction</span><span className="v">JSON · severity-sorted</span></div>
        <div className="side-line"><span className="k"><span className="serif ital">iv.</span> Reasoning</span><span className="v">claude-sonnet-4-5</span></div>
        <div className="side-line"><span className="k"><span className="serif ital">v.</span> Output</span><span className="v">PDF report</span></div>
      </div>
    </div>);

}

function Selector({ samples, selectedId, onSelect }) {
  return (
    <>
      <div className="section-head">
        <span className="num">I</span>
        <div>
          <div className="title">Select a contract to audit</div>
        </div>
        <div className="sub">{samples.length} samples · editable source</div>
      </div>

      <div className="samples">
        {samples.map((c, i) =>
        <button
          key={c.id}
          className={`sample ${selectedId === c.id ? 'active' : ''}`}
          onClick={() => onSelect(c.id)}>
          
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
              <span className="kicker">Sample {String(i + 1).padStart(2, '0')}</span>
              <span className={`badge badge-${c.severity}`}>{c.severity}</span>
            </div>
            <div className="filename">{c.name}</div>
            <div className="title serif">{c.title}</div>
            <div className="desc">{c.blurb}</div>
            <div className="foot">
              <span>{c.loc} LoC</span>
              <span>{c.findings.length} known issues</span>
            </div>
          </button>
        )}
      </div>
    </>);

}

function ConfigPanel({ findings, onRun, source }) {
  const counts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    findings.forEach((f) => {c[f.impact] = (c[f.impact] || 0) + 1;});
    return c;
  }, [findings]);
  const pragmaMatch = source.match(/pragma\s+solidity\s+([^;]+);/);

  return (
    <div className="side">
      <div className="live-findings">
        <div className="live-findings-head">
          <span className="lbl">Live static analysis</span>
          <span className="count mono">{findings.length} {findings.length === 1 ? 'issue' : 'issues'}</span>
        </div>
        <div className="live-list">
          {findings.length === 0 &&
          <div className="live-empty">No vulnerabilities detected — edit the code to introduce one.</div>
          }
          {findings.map((f, idx) =>
          <div key={f.id} className="live-item">
              <span className={`badge badge-${f.impact.toLowerCase()}`}>{f.impact[0]}</span>
              <div>
                <div className="title">{f.title}</div>
                <div className="meta">
                  <span className="mono">{f.check}</span> · {f.location}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="config">
        <div className="config-head">Audit configuration</div>
        <div className="config-body">
          <div className="config-row"><span className="k">Pragma detected</span><span className="v">{pragmaMatch ? pragmaMatch[1].trim() : '—'}</span></div>
          <div className="config-row"><span className="k">Lines of code</span><span className="v">{source.split('\n').length}</span></div>
          <div className="config-row"><span className="k">Static analyzer</span><span className="v">Slither v0.10</span></div>
          <div className="config-row"><span className="k">AI model</span><span className="v">claude-sonnet-4-5</span></div>
          <div className="config-row"><span className="k">Temperature</span><span className="v">0.2</span></div>
          <div className="config-row"><span className="k">Min confidence</span><span className="v">Medium</span></div>
        </div>
      </div>

      <button className="btn btn-accent btn-block" onClick={onRun} disabled={findings.length === 0 && false}>
        <span>Run AI audit pipeline</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
          <path d="M5 12h14M13 5l7 7-7 7" />
        </svg>
      </button>
      <div style={{ fontSize: 11, color: 'var(--ink-dim)', textAlign: 'center', fontFamily: 'JetBrains Mono, monospace', lineHeight: 1.5 }}>
        Slither &rarr; extract &rarr; Claude &rarr; report
      </div>
    </div>);

}

function App() {
  const [phase, setPhase] = useState('select'); // select | pipeline | report
  const [selectedId, setSelectedId] = useState('vault');
  const [source, setSource] = useState(SAMPLE_CONTRACTS[0].source);
  const [findings, setFindings] = useState([]);
  const [results, setResults] = useState({});

  const contract = SAMPLE_CONTRACTS.find((c) => c.id === selectedId);

  // re-analyze whenever source changes
  useEffect(() => {
    if (!window.SolidityAnalyzer) return;
    const f = window.SolidityAnalyzer.analyze(source);
    setFindings(f);
  }, [source]);

  // when sample switches, load its source
  function handleSelect(id) {
    const c = SAMPLE_CONTRACTS.find((s) => s.id === id);
    setSelectedId(id);
    setSource(c.source);
  }

  function handleAnalyze() {
    setPhase('pipeline');
  }
  function handleComplete(r) {
    setResults(r);
    setPhase('report');
  }
  function handleBack() {
    setPhase('select');
    setResults({});
  }

  const runtimeContract = {
    ...contract,
    source,
    loc: source.split('\n').length
  };

  return (
    <>
      <Masthead />
      <div className="container">
        {phase === 'select' &&
        <>
            <Leader />
            <Selector samples={SAMPLE_CONTRACTS} selectedId={selectedId} onSelect={handleSelect} />

            <div className="section-head" style={{ marginTop: 12 }}>
              <span className="num">II</span>
              <div>
                <div className="title">Editor</div>
              </div>
              <div className="sub"></div>
            </div>

            <div className="work">
              <div className="editor">
                <div className="editor-toolbar">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span className="file-pill">
                      <span className="sol-mark">S</span>
                      {contract.name}
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--ink-dim)', fontFamily: 'JetBrains Mono, monospace' }}>
                      ● modified
                    </span>
                  </div>
                  <div className="editor-meta">
                    <span>Solidity</span>
                    <span className="sep">·</span>
                    <span>{source.split('\n').length} lines</span>
                    <span className="sep">·</span>
                    <span>UTF-8</span>
                    <span className="sep">·</span>
                    <span>spaces: 4</span>
                  </div>
                </div>
                <SolidityEditor value={source} onChange={setSource} findings={findings} />
              </div>

              <ConfigPanel findings={findings} onRun={handleAnalyze} source={source} />
            </div>

            <Colophon />
          </>
        }

        {phase === 'pipeline' &&
        <>
            <div className="crumbs">
              <button onClick={handleBack}>◂ Cancel</button>
              <span className="sep">/</span>
              <span>Auditing</span>
              <span className="sep">/</span>
              <span className="cur">{contract.name}</span>
            </div>
            <PipelineRunner contract={runtimeContract} findings={findings} onComplete={handleComplete} />
          </>
        }

        {phase === 'report' &&
        <>
            <ReportView contract={runtimeContract} findings={findings} results={results} onBack={handleBack} />
            <Colophon />
          </>
        }
      </div>
    </>);

}

function Colophon() {
  return (
    <div className="colophon">
      <div>
        <div className="ttl"></div>
        
      </div>
      <div>
        <div className="ttl"></div>
        <div></div>
        <div></div>
        <div></div>
        <div></div>
      </div>
      <div>
        <div className="ttl"></div>
        <div></div>
        <div></div>
        <div style={{ marginTop: 10, fontStyle: 'italic', fontFamily: 'Newsreader, serif', fontSize: 13 }}>

        </div>
      </div>
    </div>);

}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);