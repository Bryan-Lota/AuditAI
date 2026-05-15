import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { AlertTriangle, CheckCircle2, FileCode2, FileDown, Loader2, ShieldCheck, UploadCloud } from 'lucide-react';
import './index.css';
import { createAudit, getAudit, reportUrl } from './api';

// These status labels mirror backend AuditStatus values and drive the
// real-time progress cards shown while Slither, Gemini, and ReportLab run.
const STATUSES = [
  ['queued', 'Queued'],
  ['analyzing', 'Analyzing with Slither...'],
  ['explaining', 'Generating Gemini explanations...'],
  ['reporting', 'Generating PDF report...'],
  ['complete', 'Complete'],
];

function App() {
  const [file, setFile] = useState(null);
  const [audit, setAudit] = useState(null);
  const [error, setError] = useState('');
  const [isUploading, setUploading] = useState(false);

  useEffect(() => {
    if (!audit || ['complete', 'failed'].includes(audit.status)) return undefined;
    const timer = window.setInterval(async () => {
      try {
        setAudit(await getAudit(audit.id));
      } catch (err) {
        setError(err.message);
      }
    }, 1800);
    return () => window.clearInterval(timer);
  }, [audit]);

  async function handleSubmit(event) {
    event.preventDefault();
    if (!file) return;
    setError('');
    setUploading(true);
    try {
      setAudit(await createAudit(file));
    } catch (err) {
      setError(err.message);
    } finally {
      setUploading(false);
    }
  }

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top_left,#155e75,transparent_35%),#020617] text-slate-100">
      <section className="mx-auto flex max-w-6xl flex-col gap-8 px-6 py-10">
        <header className="flex flex-col gap-5 rounded-3xl border border-white/10 bg-white/5 p-8 shadow-2xl shadow-cyan-950/40 backdrop-blur md:flex-row md:items-center md:justify-between">
          <div>
            <div className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.35em] text-cyan-300">
              <ShieldCheck className="h-5 w-5" /> AuditAI
            </div>
            <h1 className="max-w-3xl text-4xl font-black tracking-tight md:text-6xl">
              Slither-first smart contract audits with constrained Gemini reasoning.
            </h1>
            <p className="mt-4 max-w-2xl text-slate-300">
              Upload Solidity, run deterministic Slither analysis, then let Gemini explain only the vulnerabilities Slither found.
            </p>
          </div>
          <div className="rounded-2xl border border-cyan-300/30 bg-cyan-300/10 p-4 text-sm text-cyan-100">
            <p className="font-semibold">Safety constraint</p>
            <p className="mt-1 text-cyan-100/80">The LLM never invents audit findings; it only interprets normalized Slither JSON.</p>
          </div>
        </header>

        <div className="grid gap-8 lg:grid-cols-[0.85fr_1.15fr]">
          <UploadPanel file={file} isUploading={isUploading} onFile={setFile} onSubmit={handleSubmit} />
          <StatusPanel audit={audit} error={error} />
        </div>
      </section>
    </main>
  );
}

function UploadPanel({ file, isUploading, onFile, onSubmit }) {
  // Upload section: users provide a Solidity .sol file that the backend can
  // pass through pragma detection, solc-select, Slither, Gemini, and PDF output.
  return (
    <form onSubmit={onSubmit} className="rounded-3xl border border-white/10 bg-slate-900/80 p-6 shadow-xl">
      <h2 className="flex items-center gap-2 text-2xl font-bold"><UploadCloud className="text-cyan-300" /> Upload contract</h2>
      <label className="mt-6 flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-slate-600 bg-slate-950/70 p-10 text-center transition hover:border-cyan-300 hover:bg-cyan-300/5">
        <FileCode2 className="mb-4 h-12 w-12 text-cyan-300" />
        <span className="text-lg font-semibold">Choose a .sol file</span>
        <span className="mt-2 text-sm text-slate-400">The backend detects pragma, configures solc-select, and runs Slither in an isolated temp file.</span>
        <input className="hidden" type="file" accept=".sol" onChange={(event) => onFile(event.target.files?.[0] || null)} />
      </label>
      {file && <p className="mt-4 rounded-xl bg-slate-800 p-3 text-sm text-slate-200">Selected: <b>{file.name}</b></p>}
      <button disabled={!file || isUploading} className="mt-6 flex w-full items-center justify-center gap-2 rounded-2xl bg-cyan-300 px-5 py-3 font-bold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-50">
        {isUploading ? <Loader2 className="h-5 w-5 animate-spin" /> : <ShieldCheck className="h-5 w-5" />}
        Start audit
      </button>
    </form>
  );
}

function StatusPanel({ audit, error }) {
  // Status section: polls backend progress and highlights the active pipeline
  // stage so users know whether analysis, explanations, or reporting is active.
  const currentIndex = useMemo(() => Math.max(0, STATUSES.findIndex(([status]) => status === audit?.status)), [audit]);
  return (
    <section className="rounded-3xl border border-white/10 bg-slate-900/80 p-6 shadow-xl">
      <h2 className="text-2xl font-bold">Audit status</h2>
      {error && <div className="mt-4 rounded-xl border border-red-400/30 bg-red-500/10 p-4 text-red-200"><AlertTriangle className="mr-2 inline h-5 w-5" />{error}</div>}
      {!audit && <p className="mt-6 text-slate-400">Upload a contract to begin.</p>}
      {audit && (
        <>
          <div className="mt-5 grid gap-3 sm:grid-cols-5">
            {STATUSES.map(([status, label], index) => (
              <div key={status} className={`rounded-2xl border p-3 text-sm ${index <= currentIndex ? 'border-cyan-300/40 bg-cyan-300/10 text-cyan-100' : 'border-white/10 bg-slate-950 text-slate-500'}`}>
                {index < currentIndex || audit.status === 'complete' ? <CheckCircle2 className="mb-2 h-5 w-5" /> : <Loader2 className={`mb-2 h-5 w-5 ${index === currentIndex ? 'animate-spin' : ''}`} />}
                {label}
              </div>
            ))}
          </div>
          {audit.status === 'failed' && <p className="mt-5 rounded-xl bg-red-500/10 p-4 text-red-200">{audit.error_message}</p>}
          <Findings audit={audit} />
        </>
      )}
    </section>
  );
}

function Findings({ audit }) {
  // Findings section: displays Slither-originated findings and links the
  // generated PDF once the backend report record exists.
  return (
    <div className="mt-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.25em] text-slate-500">Session</p>
          <h3 className="font-mono text-sm text-slate-300">{audit.id}</h3>
        </div>
        {audit.report && <a className="flex items-center gap-2 rounded-xl bg-white px-4 py-2 font-semibold text-slate-950" href={reportUrl(audit.id)}><FileDown className="h-4 w-4" /> PDF</a>}
      </div>
      <div className="mt-5 space-y-4">
        {audit.findings.length === 0 && audit.status === 'complete' && <p className="rounded-xl bg-emerald-400/10 p-4 text-emerald-200">Slither reported no findings.</p>}
        {audit.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}
      </div>
    </div>
  );
}

function FindingCard({ finding }) {
  // Finding card section: combines deterministic Slither metadata with Gemini's
  // bounded explanation, exploitability assessment, and remediation snippet.
  const tone = finding.severity === 'High' ? 'bg-red-500/15 text-red-200 border-red-400/30' : finding.severity === 'Medium' ? 'bg-amber-500/15 text-amber-100 border-amber-400/30' : 'bg-blue-500/15 text-blue-100 border-blue-400/30';
  return (
    <article className="rounded-2xl border border-white/10 bg-slate-950/80 p-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className={`rounded-full border px-3 py-1 text-xs font-bold uppercase ${tone}`}>{finding.severity}</span>
        <h4 className="text-lg font-bold">{finding.vulnerability_type}</h4>
        <span className="text-sm text-slate-500">Line {finding.line_number || 'n/a'}</span>
      </div>
      <p className="mt-3 text-sm text-slate-400">{finding.slither_description}</p>
      {finding.explanation && <p className="mt-4 text-slate-200"><b>Gemini explanation:</b> {finding.explanation}</p>}
      {finding.exploitability && <p className="mt-3 text-slate-300"><b>Exploitability:</b> {finding.exploitability}</p>}
      {finding.remediation_snippet && <pre className="mt-4 overflow-x-auto rounded-xl bg-black/60 p-4 text-sm text-cyan-100"><code>{finding.remediation_snippet}</code></pre>}
    </article>
  );
}

createRoot(document.getElementById('root')).render(<App />);
