// Audit pipeline animation — editorial light theme.
// Stages: Upload → Slither → Extract → Claude → PDF

const SLITHER_DETECTORS = [
  'reentrancy-eth', 'reentrancy-no-eth', 'reentrancy-events',
  'uninitialized-state', 'uninitialized-storage', 'uninitialized-local',
  'shadowing-state', 'shadowing-builtin',
  'tx-origin', 'arbitrary-send-eth', 'arbitrary-send-erc20',
  'controlled-array-length', 'controlled-delegatecall',
  'msg-value-loop', 'incorrect-equality', 'locked-ether',
  'unchecked-send', 'unchecked-transfer', 'unchecked-lowlevel',
  'unused-return', 'mapping-deletion',
  'tautology', 'boolean-cst',
  'divide-before-multiply', 'incorrect-modifier',
  'erc20-interface', 'pragma', 'solc-version',
  'low-level-calls', 'missing-zero-check',
  'integer-overflow', 'missing-access-control', 'timestamp',
  'weak-prng', 'suicidal',
  'calls-loop', 'reentrancy-unlimited-gas',
];

function PipelineRunner({ contract, findings, onComplete }) {
  const [stage, setStage] = React.useState(0);
  const [detectorLines, setDetectorLines] = React.useState([]);
  const [reasoningStates, setReasoningStates] = React.useState({});
  const cancelled = React.useRef(false);

  React.useEffect(() => {
    cancelled.current = false;
    run();
    return () => { cancelled.current = true; };
  }, []);

  async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  async function run() {
    setStage(0);
    await sleep(550);
    if (cancelled.current) return;

    setStage(1);
    const hits = new Set(findings.map(f => f.check));
    const seq = SLITHER_DETECTORS.slice().sort(() => Math.random() - 0.5);
    for (let i = 0; i < seq.length; i++) {
      if (cancelled.current) return;
      const d = seq[i];
      const isHit = hits.has(d);
      const sev = isHit ? findings.find(f => f.check === d).impact : null;
      setDetectorLines(prev => [...prev.slice(-6), { d, hit: isHit, sev, id: Math.random() }]);
      await sleep(isHit ? 200 : 45);
    }
    await sleep(400);
    if (cancelled.current) return;

    setStage(2);
    await sleep(700);
    if (cancelled.current) return;

    setStage(3);
    const results = {};
    for (const finding of findings) {
      if (cancelled.current) return;
      setReasoningStates(prev => ({ ...prev, [finding.id]: 'active' }));
      try {
        results[finding.id] = await callClaude(contract, finding);
      } catch (e) {
        results[finding.id] = fallback(finding);
      }
      setReasoningStates(prev => ({ ...prev, [finding.id]: 'done' }));
      await sleep(150);
    }
    await sleep(400);
    if (cancelled.current) return;

    setStage(4);
    await sleep(750);
    if (cancelled.current) return;

    setStage(5);
    await sleep(250);
    onComplete(results);
  }

  async function callClaude(contract, finding) {
    const prompt = `You are a professional smart contract security auditor.

CONTRACT (${contract.name}):
\`\`\`solidity
${contract.source}
\`\`\`

SLITHER FINDING:
- Detector: ${finding.check}
- Impact: ${finding.impact}
- Confidence: ${finding.confidence}
- Location: ${finding.location}
- Lines: ${finding.lines.join(', ')}
- Description: ${finding.description}

Respond ONLY with raw JSON (no markdown fences, no preamble) in this exact shape:
{
  "explanation": "2-3 sentence plain-English explanation accessible to developers without security expertise.",
  "danger": "2-3 sentences on the concrete exploit scenario specific to THIS contract's code.",
  "severity": "Critical|High|Medium|Low|Informational",
  "fix": "A short corrected Solidity code snippet. Use '+ ' prefix for added lines, '- ' prefix for removed lines, no prefix for unchanged context. Maximum 12 lines."
}`;
    const response = await window.claude.complete(prompt);
    const match = response.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('no json');
    return JSON.parse(match[0]);
  }

  function fallback(f) {
    return {
      explanation: f.description,
      danger: 'Severity ' + f.impact + ' — remediate before deployment.',
      severity: f.impact,
      fix: '// see SWC registry for ' + f.check
    };
  }

  const stages = [
    { name: 'Upload',             detail: 'multipart parse · file integrity · syntax validation' },
    { name: 'Slither Analysis',   detail: 'SlithIR conversion · 90+ detectors · confidence filtering' },
    { name: 'Finding Extraction', detail: 'JSON parse · severity sort · noise filter' },
    { name: 'AI Reasoning',       detail: 'claude-sonnet-4-5 · temp 0.2 · chain-of-thought' },
    { name: 'Report Generation', detail: 'ReportLab · executive summary · remediation checklist' },
  ];

  return (
    <div className="pipeline fade-in">
      <div className="pipeline-head">
        <span className="title">Auditing <em className="ital">{contract.name}</em></span>
        <span className="status">{stage < 5 ? 'In progress' : 'Complete'}</span>
      </div>

      <div className="stages">
        {stages.map((s, i) => {
          const isActive = stage === i;
          const isDone = stage > i;
          return (
            <div key={i} className={`stage ${isActive ? 'active' : ''} ${isDone ? 'done' : ''}`}>
              <div className="stage-num">{String(i + 1).padStart(2, '0')}</div>
              <div>
                <div className="stage-name">{s.name}</div>
                <div className="stage-detail">{s.detail}</div>
              </div>
              <div className="stage-status">
                <span className="ind" />
                {isActive ? 'running' : isDone ? 'done' : 'idle'}
              </div>
            </div>
          );
        })}
      </div>

      {stage === 1 && (
        <div className="ticker">
          {detectorLines.map(l => (
            <div key={l.id} className={`ticker-line ${l.hit ? 'hit' : ''}`}>
              <span className="arrow">{l.hit ? '✗' : '·'}</span>
              {l.d.padEnd(28, ' ')}
              {l.hit ? `  →  ${l.sev.toUpperCase()} match` : '  →  clean'}
            </div>
          ))}
        </div>
      )}

      {stage >= 3 && findings.length > 0 && (
        <div className="reasoning">
          {findings.map(f => {
            const st = reasoningStates[f.id] || 'pending';
            return (
              <div key={f.id} className="reasoning-item">
                <span className="ind" style={{
                  border: st === 'pending' ? '1.5px solid var(--ink-faint)' : undefined,
                  background: st === 'done' ? 'var(--ok)' : undefined,
                  borderColor: st === 'active' ? 'var(--accent)' : st === 'done' ? 'var(--ok)' : undefined,
                  borderTopColor: st === 'active' ? 'transparent' : undefined,
                  borderRightColor: st === 'active' ? 'transparent' : undefined,
                  animation: st === 'active' ? 'spin 0.8s linear infinite' : 'none'
                }} />
                <span className="label">
                  {st === 'active' ? 'Reasoning over ' : st === 'done' ? 'Explained ' : 'Queued · '}
                  <span className="det">{f.check}</span>
                </span>
                <span className={`badge badge-${f.impact.toLowerCase()}`}>{f.impact}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

window.PipelineRunner = PipelineRunner;
