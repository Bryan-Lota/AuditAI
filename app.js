// AuditAI — dependency-free browser app.
// Renders the sample selector, live Solidity analyzer, pipeline animation, and report.

(function () {
  const { SAMPLE_CONTRACTS, SolidityAnalyzer } = window;

  const state = {
    selectedId: SAMPLE_CONTRACTS[0]?.id,
    source: SAMPLE_CONTRACTS[0]?.source || '',
    phase: 'edit',
    stage: 0,
    aiResults: {},
  };

  const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  const STAGES = [
    { title: 'Upload', detail: 'Contract source loaded into the audit workspace.' },
    { title: 'Static analysis', detail: 'Pattern detectors scan for Slither-style vulnerability signals.' },
    { title: 'Extraction', detail: 'Findings are normalized, deduplicated, and sorted by severity.' },
    { title: 'Reasoning', detail: 'AI-style explanations and remediation notes are generated locally.' },
    { title: 'Report', detail: 'The final audit report is assembled for review or printing.' },
  ];

  function selectedContract() {
    return SAMPLE_CONTRACTS.find((contract) => contract.id === state.selectedId) || SAMPLE_CONTRACTS[0];
  }

  function currentContract() {
    const selected = selectedContract();
    return {
      ...selected,
      source: state.source,
      loc: state.source.split('\n').length,
      name: selected?.name || 'CustomContract.sol',
    };
  }

  function findings() {
    if (!SolidityAnalyzer || typeof SolidityAnalyzer.analyze !== 'function') return [];
    return SolidityAnalyzer.analyze(state.source);
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function sevClass(severity) {
    return String(severity || '').toLowerCase();
  }

  function severityRank(severity) {
    return ({ Critical: 4, High: 3, Medium: 2, Low: 1, Informational: 0 })[severity] ?? 0;
  }

  function countBySeverity(items) {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    items.forEach((finding) => {
      counts[finding.impact] = (counts[finding.impact] || 0) + 1;
    });
    return counts;
  }

  function overallRisk(items) {
    if (!items.length) return 'Clean';
    const max = Math.max(...items.map((finding) => severityRank(finding.impact)));
    return ['Clean', 'Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'][max];
  }

  function riskClass(label) {
    return ({
      'Critical Risk': 'crit',
      'High Risk': 'high',
      'Medium Risk': 'med',
      'Low Risk': 'low',
      Clean: 'ok',
    })[label] || '';
  }

  function riskColor(label) {
    return ({
      'Critical Risk': 'var(--crit)',
      'High Risk': 'var(--high)',
      'Medium Risk': 'var(--med)',
      'Low Risk': 'var(--low)',
      Clean: 'var(--ok)',
    })[label] || 'var(--ink)';
  }

  function sortedFindings(items) {
    return [...items].sort((a, b) => {
      const severityDelta = severityRank(b.impact) - severityRank(a.impact);
      if (severityDelta) return severityDelta;
      return (a.lines?.[0] || 0) - (b.lines?.[0] || 0);
    });
  }

  function generateFindingText(finding) {
    const location = finding.location || 'the highlighted code';
    const title = finding.title || finding.check;
    const fixMap = {
      'tx-origin': `- require(tx.origin == admin, "not admin");\n+ require(msg.sender == admin, "not admin");`,
      'reentrancy-eth': `- (bool ok, ) = msg.sender.call{value: amount}("");\n- require(ok, "transfer failed");\n- balances[msg.sender] -= amount;\n+ balances[msg.sender] -= amount;\n+ (bool ok, ) = msg.sender.call{value: amount}("");\n+ require(ok, "transfer failed");`,
      'unchecked-send': `- payable(highestBidder).send(highestBid);\n+ (bool refunded, ) = payable(highestBidder).call{value: highestBid}("");\n+ require(refunded, "refund failed");`,
      'unchecked-lowlevel': `- target.call(data);\n+ (bool ok, ) = target.call(data);\n+ require(ok, "low-level call failed");`,
      'missing-access-control': `+ modifier onlyOwner() {\n+     require(msg.sender == owner, "not owner");\n+     _;\n+ }\n- function setOwner(address newOwner) external {\n+ function setOwner(address newOwner) external onlyOwner {`,
      timestamp: `- require(block.timestamp <= deadline, "expired");\n+ // Avoid timestamp-dependent value logic where possible.\n+ require(block.number <= deadlineBlock, "expired");`,
      'integer-overflow': `- balanceOf[msg.sender] -= amount;\n+ require(balanceOf[msg.sender] >= amount, "insufficient balance");\n+ unchecked { balanceOf[msg.sender] -= amount; }`,
      'missing-zero-check': `+ require(to != address(0), "zero address");`,
      'locked-ether': `- payable(beneficiary).transfer(highestBid);\n+ (bool ok, ) = payable(beneficiary).call{value: highestBid}("");\n+ require(ok, "transfer failed");`,
      suicidal: `- selfdestruct(payable(msg.sender));\n+ require(msg.sender == owner, "not owner");\n+ selfdestruct(payable(owner));`,
      'low-level-calls': `+ Prefer typed interface calls when the target ABI is known.\n+ If a low-level call is required, validate the target and check success.`,
      'solc-version': `- pragma solidity ^0.7.6;\n+ pragma solidity ^0.8.20;`,
    };

    return {
      explanation: `${title} was detected at ${location}. The flagged pattern can make contract behavior differ from the developer's intent and should be fixed before deployment.`,
      danger: `An attacker can focus on this code path because it is reachable from the contract interface. If exploited, the practical impact is ${String(finding.impact || 'unknown').toLowerCase()} severity for users or funds.`,
      fix: fixMap[finding.check] || '+ Add validation, authorization, and explicit error handling around the flagged statement.',
    };
  }

  function enrichFindings(items) {
    state.aiResults = {};
    items.forEach((finding) => {
      state.aiResults[finding.id] = generateFindingText(finding);
    });
  }

  function masthead() {
    const date = new Date().toLocaleDateString('en-GB', {
      weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
    });
    return `
      <div class="masthead">
        <div class="masthead-inner">
          <div class="brand">Audit<span class="ital">AI</span></div>
          <div class="masthead-meta serif">${escapeHtml(date)}</div>
          <div class="masthead-tools">
            <span class="item"><span class="status-dot"></span>local analyzer</span>
            <span class="item">Slither-style rules</span>
            <span class="item">${SolidityAnalyzer.detectors.length} detectors</span>
          </div>
        </div>
      </div>`;
  }

  function leader() {
    return `
      <div class="leader">
        <div>
          <div class="leader-eyebrow">AI-Powered Smart Contract Auditing</div>
          <h1 class="leader-title">Static analysis,<br>explained in <span class="em">plain English.</span></h1>
          <p class="leader-deck serif">AuditAI combines Slither-style static analysis with local reasoning to produce human-readable audit reports for Solidity smart contracts.</p>
        </div>
        <div class="leader-divider"></div>
        <div class="leader-side">
          <h3>The five-layer pipeline</h3>
          ${['Upload .sol file', 'Static analysis', 'Finding extraction', 'Reasoning', 'Report output'].map((item, index) => `
            <div class="side-line"><span class="k"><span class="serif ital">${index + 1}.</span> ${escapeHtml(item)}</span><span class="v">ready</span></div>`).join('')}
        </div>
      </div>`;
  }

  function renderSelector(contract, items) {
    return `
      <div class="section-head">
        <span class="num">I</span><div><div class="title">Select a contract to audit</div></div>
        <div class="sub">${SAMPLE_CONTRACTS.length} samples · editable source</div>
      </div>
      <div class="samples">
        ${SAMPLE_CONTRACTS.map((sample, index) => `
          <button class="sample ${sample.id === contract.id ? 'active' : ''}" data-action="select" data-id="${escapeHtml(sample.id)}">
            <div style="display:flex;justify-content:space-between;align-items:baseline">
              <span class="kicker">Sample ${String(index + 1).padStart(2, '0')}</span>
              <span class="badge badge-${escapeHtml(sample.severity)}">${escapeHtml(sample.severity)}</span>
            </div>
            <div class="filename">${escapeHtml(sample.name)}</div>
            <div class="title serif">${escapeHtml(sample.title)}</div>
            <div class="desc">${escapeHtml(sample.blurb)}</div>
            <div class="foot"><span>${sample.loc} LoC</span><span>${sample.findings.length} known issues</span></div>
          </button>`).join('')}
      </div>`;
  }

  function renderLiveFindings(items) {
    return `
      <div class="live-findings">
        <div class="live-findings-head"><span class="lbl">Live static analysis</span><span class="count mono">${items.length} ${items.length === 1 ? 'issue' : 'issues'}</span></div>
        <div class="live-list">
          ${items.length ? items.map((finding) => `
            <div class="live-item">
              <span class="badge badge-${sevClass(finding.impact)}">${escapeHtml(finding.impact[0])}</span>
              <div><div class="title">${escapeHtml(finding.title)}</div><div class="meta"><span class="mono">${escapeHtml(finding.check)}</span> · ${escapeHtml(finding.location)}</div></div>
            </div>`).join('') : '<div class="live-empty">No vulnerabilities detected — edit the code to introduce one.</div>'}
        </div>
      </div>`;
  }

  function renderConfig(items) {
    const counts = countBySeverity(items);
    const pragma = state.source.match(/pragma\s+solidity\s+([^;]+);/)?.[1] || 'not found';
    return `
      <div class="config">
        <div class="config-head">Audit configuration</div>
        <div class="config-row"><span>Compiler pragma</span><strong class="mono">${escapeHtml(pragma)}</strong></div>
        <div class="config-row"><span>Detectors enabled</span><strong class="mono">${SolidityAnalyzer.detectors.length}</strong></div>
        <div class="config-row"><span>Critical / High</span><strong class="mono">${counts.Critical} / ${counts.High}</strong></div>
        <button class="run-btn" data-action="run">Run full audit pipeline</button>
      </div>`;
  }

  function renderEditor(contract, items) {
    return `
      <div class="workspace">
        <div class="editor-pane">
          <div class="editor-head"><div><div class="kicker">Source</div><div class="filename">${escapeHtml(contract.name)}</div></div><div class="mono">${state.source.split('\n').length} lines</div></div>
          <textarea id="source-editor" class="editor-textarea" spellcheck="false">${escapeHtml(state.source)}</textarea>
        </div>
        <div class="side">${renderLiveFindings(items)}${renderConfig(items)}</div>
      </div>`;
  }

  function renderEdit() {
    const contract = currentContract();
    const items = findings();
    return `${leader()}${renderSelector(contract, items)}${renderEditor(contract, items)}`;
  }

  function renderPipeline() {
    const items = findings();
    return `
      <div class="pipeline-wrap fade-in">
        <div class="section-head"><span class="num">II</span><div><div class="title">Running audit pipeline</div></div><div class="sub">${items.length} findings detected</div></div>
        <div class="pipeline">
          ${STAGES.map((stage, index) => `
            <div class="pipe-step ${index < state.stage ? 'done' : ''} ${index === state.stage ? 'active' : ''}">
              <div class="pipe-num">${String(index + 1).padStart(2, '0')}</div>
              <div><div class="pipe-title">${escapeHtml(stage.title)}</div><div class="pipe-detail">${escapeHtml(stage.detail)}</div></div>
            </div>`).join('')}
        </div>
      </div>`;
  }

  function fixDiff(code) {
    return `<pre class="fix-code">${String(code || '').split('\n').map((line) => {
      const add = line.startsWith('+ ');
      const rem = line.startsWith('- ');
      const stripped = add || rem ? line.slice(2) : line;
      return `<div class="fix-line ${add ? 'add' : rem ? 'rem' : ''}"><span class="marker">${add ? '+' : rem ? '−' : ' '}</span>${escapeHtml(stripped)}</div>`;
    }).join('')}</pre>`;
  }

  function renderReport() {
    const contract = currentContract();
    const items = sortedFindings(findings());
    if (!Object.keys(state.aiResults).length) enrichFindings(items);
    const counts = countBySeverity(items);
    const risk = overallRisk(items);
    return `
      <div class="report fade-in">
        <div class="report-actions"><button class="run-btn ghost" data-action="back">Back to editor</button><button class="run-btn" data-action="print">Print / save PDF</button></div>
        <div class="report-hero">
          <div><div class="kicker">Audit report</div><h2 class="serif">${escapeHtml(contract.name)}</h2><p>Generated from the current editor contents using local Slither-style checks.</p></div>
          <div class="risk-card ${riskClass(risk)}"><div class="lbl">Overall risk</div><div class="risk">${escapeHtml(risk)}</div><div class="mono">${items.length} findings</div></div>
        </div>
        <div class="stats">
          ${SEVERITIES.map((severity) => `<div class="stat ${sevClass(severity).replace('informational', '')}"><div class="num">${counts[severity]}</div><div class="lbl">${severity}</div></div>`).join('')}
        </div>
        <div class="body-grid">
          <div class="body-label">Executive<br>Summary</div>
          <div class="body-prose"><p class="dropcap">AuditAI analyzed <strong>${escapeHtml(contract.name)}</strong> (${contract.loc} lines of Solidity). The contract was rated <strong style="color:${riskColor(risk)}">${escapeHtml(risk)}</strong> with <strong>${items.length}</strong> findings.</p><p>${items.length ? 'Resolve all Critical and High severity findings before production deployment.' : 'No vulnerabilities were detected by the configured static analyzers. Manual review is still recommended.'}</p></div>
        </div>
        <div class="section-head" style="margin-bottom:0"><span class="num">II</span><div><div class="title">Detailed findings</div></div><div class="sub">${items.length} sorted by severity</div></div>
        ${items.length ? `<div class="findings stagger">${items.map((finding, index) => {
          const result = state.aiResults[finding.id] || generateFindingText(finding);
          const lineLabel = finding.lines?.length > 1 ? `lines ${finding.lines[0]}–${finding.lines[finding.lines.length - 1]}` : `line ${finding.lines?.[0] || '?'}`;
          return `<div class="finding"><div class="finding-head"><div class="finding-num">${String(index + 1).padStart(2, '0')}</div><div><h3 class="finding-title">${escapeHtml(finding.title)}</h3><div class="finding-meta">${escapeHtml(contract.name)} · ${escapeHtml(finding.location)} · ${escapeHtml(lineLabel)} · detector: <code>${escapeHtml(finding.check)}</code> · confidence: ${escapeHtml(finding.confidence)}</div></div><span class="badge badge-${sevClass(finding.impact)}">${escapeHtml(finding.impact)}</span></div><div class="finding-grid"><div class="field-label">Slither<br>detection</div><div class="field-body field-row">${escapeHtml(finding.description)}</div><div class="field-label">Explanation<div class="ai-tag">— generated locally</div></div><div class="field-body field-row">${escapeHtml(result.explanation)}</div><div class="field-label">Exploit<br>scenario<div class="ai-tag">— generated locally</div></div><div class="field-body field-row">${escapeHtml(result.danger)}</div><div class="field-label">Recommended<br>fix<div class="ai-tag">— generated locally</div></div><div class="field-body field-row">${fixDiff(result.fix)}</div></div></div>`;
        }).join('')}</div>` : '<div class="live-empty" style="padding:60px 20px;text-align:center">No vulnerabilities detected.</div>'}
      </div>`;
  }

  function render() {
    const root = document.getElementById('root');
    if (!root) return;
    const body = state.phase === 'pipeline' ? renderPipeline() : state.phase === 'report' ? renderReport() : renderEdit();
    root.innerHTML = `${masthead()}<main class="container">${body}<div class="colophon"><div><div class="ttl">AuditAI</div>Dependency-free demo build.</div><div><div class="ttl">Analyzer</div>Runs entirely in the browser.</div><div><div class="ttl">Note</div>Static checks supplement, but do not replace, a professional audit.</div></div></main>`;

    const editor = document.getElementById('source-editor');
    if (editor) {
      editor.addEventListener('input', (event) => {
        state.source = event.target.value;
        render();
        const nextEditor = document.getElementById('source-editor');
        if (nextEditor) {
          nextEditor.focus();
          nextEditor.selectionStart = event.target.selectionStart;
          nextEditor.selectionEnd = event.target.selectionEnd;
        }
      });
    }
  }

  function runPipeline() {
    state.phase = 'pipeline';
    state.stage = 0;
    render();
    const items = findings();
    const timer = setInterval(() => {
      state.stage += 1;
      if (state.stage >= STAGES.length) {
        clearInterval(timer);
        enrichFindings(items);
        state.phase = 'report';
      }
      render();
    }, 650);
  }

  document.addEventListener('click', (event) => {
    const target = event.target.closest('[data-action]');
    if (!target) return;
    const action = target.dataset.action;
    if (action === 'select') {
      const next = SAMPLE_CONTRACTS.find((contract) => contract.id === target.dataset.id);
      if (next) {
        state.selectedId = next.id;
        state.source = next.source;
        state.aiResults = {};
        state.phase = 'edit';
        render();
      }
    }
    if (action === 'run') runPipeline();
    if (action === 'back') {
      state.phase = 'edit';
      render();
    }
    if (action === 'print') window.print();
  });

  document.addEventListener('DOMContentLoaded', render);
})();
