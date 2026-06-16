import React, { useState } from 'react';
import {
  Shield, ChevronRight, Download, FileText, FileCode, Printer,
  ChevronDown, Book,
} from 'lucide-react';
import { SECTIONS, GUIDE_TITLE, GUIDE_SUBTITLE, GUIDE_VERSION } from '../data/userGuideData';

// ---------------------------------------------------------------------------
// Block renderers
// ---------------------------------------------------------------------------
function BlockP({ block }) {
  return <p className="text-gray-300 leading-relaxed mb-4 text-sm">{block.text}</p>;
}

function BlockH3({ block }) {
  return (
    <h3 className="text-green-400 text-sm font-semibold uppercase tracking-wider mt-6 mb-3">
      {block.text}
    </h3>
  );
}

function BlockUl({ block }) {
  return (
    <ul className="mb-4 space-y-1.5 pl-2">
      {block.items.map((item, i) => (
        <li key={i} className="flex gap-2 text-sm text-gray-300">
          <span className="text-green-500 mt-1 flex-shrink-0">•</span>
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

function BlockOl({ block }) {
  return (
    <ol className="mb-4 space-y-2 pl-2">
      {block.items.map((item, i) => (
        <li key={i} className="flex gap-2.5 text-sm text-gray-300">
          <span className="text-green-500 font-mono font-semibold flex-shrink-0 w-5">{i + 1}.</span>
          <span>{item}</span>
        </li>
      ))}
    </ol>
  );
}

function BlockTip({ block }) {
  return (
    <div className="mb-4 flex gap-3 bg-green-950/30 border border-green-800/40 rounded-lg p-3.5">
      <div className="flex-shrink-0 mt-0.5">
        <span className="text-[10px] font-bold uppercase tracking-widest text-green-400 bg-green-900/40 px-1.5 py-0.5 rounded">
          {block.label || 'Tip'}
        </span>
      </div>
      <p className="text-sm text-green-200/80 leading-relaxed">{block.text}</p>
    </div>
  );
}

function BlockTable({ block }) {
  return (
    <div className="mb-4 overflow-x-auto rounded-lg border border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-900/80">
            {block.headers.map((h, i) => (
              <th
                key={i}
                className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-widest text-gray-400 border-b border-gray-800"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {block.rows.map((row, ri) => (
            <tr key={ri} className={ri % 2 === 0 ? 'bg-gray-950/40' : 'bg-gray-900/30'}>
              {row.map((cell, ci) => (
                <td key={ci} className="px-4 py-2.5 text-gray-300 border-b border-gray-800/50">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function GuideBlock({ block }) {
  switch (block.type) {
    case 'p':      return <BlockP block={block} />;
    case 'h3':     return <BlockH3 block={block} />;
    case 'ul':     return <BlockUl block={block} />;
    case 'ol':     return <BlockOl block={block} />;
    case 'tip':    return <BlockTip block={block} />;
    case 'table':  return <BlockTable block={block} />;
    default:       return null;
  }
}

// ---------------------------------------------------------------------------
// Export helpers
// ---------------------------------------------------------------------------
function blockToTxt(block) {
  switch (block.type) {
    case 'p':   return block.text + '\n';
    case 'h3':  return block.text.toUpperCase() + '\n';
    case 'ul':  return block.items.map(i => `  • ${i}`).join('\n') + '\n';
    case 'ol':  return block.items.map((i, n) => `  ${n + 1}. ${i}`).join('\n') + '\n';
    case 'tip': return `[${block.label || 'TIP'}] ${block.text}\n`;
    case 'table': {
      const cols = block.headers.map((h, ci) =>
        Math.max(h.length, ...block.rows.map(r => (r[ci] || '').length))
      );
      const sep = cols.map(w => '─'.repeat(w + 2)).join('┼');
      const header = '│' + block.headers.map((h, i) => ` ${h.padEnd(cols[i])} `).join('│') + '│';
      const rows = block.rows.map(r =>
        '│' + r.map((c, i) => ` ${(c || '').padEnd(cols[i])} `).join('│') + '│'
      );
      return ['┌' + sep + '┐', header, '├' + sep + '┤', ...rows, '└' + sep + '┘'].join('\n') + '\n';
    }
    default: return '';
  }
}

function blockToMd(block) {
  switch (block.type) {
    case 'p':   return block.text + '\n';
    case 'h3':  return `### ${block.text}\n`;
    case 'ul':  return block.items.map(i => `- ${i}`).join('\n') + '\n';
    case 'ol':  return block.items.map((i, n) => `${n + 1}. ${i}`).join('\n') + '\n';
    case 'tip': return `> **${block.label || 'Tip'}:** ${block.text}\n`;
    case 'table': {
      const header = '| ' + block.headers.join(' | ') + ' |';
      const sep = '| ' + block.headers.map(() => '---').join(' | ') + ' |';
      const rows = block.rows.map(r => '| ' + r.join(' | ') + ' |');
      return [header, sep, ...rows].join('\n') + '\n';
    }
    default: return '';
  }
}

function blockToHtml(block) {
  switch (block.type) {
    case 'p':   return `<p>${block.text}</p>`;
    case 'h3':  return `<h3>${block.text}</h3>`;
    case 'ul':  return `<ul>${block.items.map(i => `<li>${i}</li>`).join('')}</ul>`;
    case 'ol':  return `<ol>${block.items.map(i => `<li>${i}</li>`).join('')}</ol>`;
    case 'tip': return `<div class="tip"><strong>${block.label || 'Tip'}:</strong> ${block.text}</div>`;
    case 'table': {
      const ths = block.headers.map(h => `<th>${h}</th>`).join('');
      const trs = block.rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('');
      return `<table><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
    }
    default: return '';
  }
}

function downloadBlob(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportTxt() {
  const dateLine = `Version ${GUIDE_VERSION}  ·  Generated ${new Date().toLocaleDateString()}`;
  const lines = [
    GUIDE_TITLE,
    GUIDE_SUBTITLE,
    dateLine,
    '',
    '='.repeat(60),
    '',
  ];

  SECTIONS.forEach((s, si) => {
    lines.push(`${si + 1}. ${s.title.toUpperCase()}`);
    lines.push('─'.repeat(40));
    lines.push('');
    s.blocks.forEach(b => {
      lines.push(blockToTxt(b));
      lines.push('');
    });
    lines.push('');
  });

  downloadBlob(lines.join('\n'), 'defense-halo-user-guide.txt', 'text/plain');
}

function exportMarkdown() {
  const lines = [
    `# ${GUIDE_TITLE}`,
    `## ${GUIDE_SUBTITLE}`,
    '',
    `*Version ${GUIDE_VERSION} · Generated ${new Date().toLocaleDateString()}*`,
    '',
    '---',
    '',
  ];

  SECTIONS.forEach((s, si) => {
    lines.push(`## ${si + 1}. ${s.title}`);
    lines.push('');
    s.blocks.forEach(b => {
      lines.push(blockToMd(b));
      lines.push('');
    });
    lines.push('---');
    lines.push('');
  });

  downloadBlob(lines.join('\n'), 'defense-halo-user-guide.md', 'text/markdown');
}

function exportPDF() {
  const sectionHtml = SECTIONS.map((s, si) => `
    <section>
      <h2>${si + 1}. ${s.title}</h2>
      ${s.blocks.map(blockToHtml).join('\n')}
      <hr>
    </section>
  `).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${GUIDE_TITLE} — ${GUIDE_SUBTITLE}</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;max-width:820px;margin:40px auto;color:#111;line-height:1.6;font-size:13px;}
    h1{color:#16a34a;font-size:22px;margin:0;}
    .subtitle{color:#4b5563;font-size:13px;margin:4px 0 4px;}
    .meta{color:#9ca3af;font-size:11px;margin-bottom:28px;}
    h2{color:#111827;font-size:15px;border-bottom:2px solid #22c55e;padding-bottom:4px;margin-top:28px;page-break-after:avoid;}
    h3{color:#374151;font-size:13px;font-weight:700;margin:18px 0 6px;text-transform:uppercase;letter-spacing:.05em;}
    p{margin:0 0 10px;}
    ul,ol{padding-left:20px;margin:0 0 10px;}
    li{margin:3px 0;}
    .tip{background:#f0fdf4;border-left:4px solid #22c55e;padding:9px 14px;margin:10px 0;border-radius:0 4px 4px 0;}
    .tip strong{color:#15803d;}
    table{border-collapse:collapse;width:100%;margin:10px 0;}
    th{background:#f3f4f6;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.04em;}
    th,td{border:1px solid #d1d5db;padding:6px 11px;text-align:left;vertical-align:top;}
    hr{border:none;border-top:1px solid #e5e7eb;margin:28px 0;}
    @page{margin:2cm;}
    @media print{body{margin:0;} section{page-break-inside:avoid;}}
  </style>
</head>
<body>
  <h1>DEFENSE HALO</h1>
  <div class="subtitle">Customer CVE Analyzer — ${GUIDE_SUBTITLE}</div>
  <div class="meta">Version ${GUIDE_VERSION} · Generated ${new Date().toLocaleDateString()}</div>
  ${sectionHtml}
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) { alert('Pop-up blocked. Allow pop-ups and try again.'); return; }
  win.document.write(html);
  win.document.close();
  setTimeout(() => win.print(), 400);
}

// ---------------------------------------------------------------------------
// Export dropdown
// ---------------------------------------------------------------------------
function ExportMenu() {
  const [open, setOpen] = useState(false);

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-700 bg-gray-900 text-gray-400 hover:text-green-400 hover:border-green-500/40 transition-colors"
      >
        <Download size={13} />
        <span>Export</span>
        <ChevronDown size={11} className={`transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-1.5 z-20 bg-gray-900 border border-gray-700 rounded-lg shadow-xl w-44 overflow-hidden">
            <button
              onClick={() => { exportTxt(); setOpen(false); }}
              className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-xs text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
            >
              <FileText size={13} className="text-gray-500" />
              Plain Text (.txt)
            </button>
            <button
              onClick={() => { exportMarkdown(); setOpen(false); }}
              className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-xs text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
            >
              <FileCode size={13} className="text-gray-500" />
              Markdown (.md)
            </button>
            <button
              onClick={() => { exportPDF(); setOpen(false); }}
              className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-xs text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
            >
              <Printer size={13} className="text-gray-500" />
              PDF (Print)
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function UserGuide() {
  const [activeId, setActiveId] = useState(SECTIONS[0].id);

  const activeSection = SECTIONS.find(s => s.id === activeId) || SECTIONS[0];
  const activeIndex = SECTIONS.findIndex(s => s.id === activeId);

  const goNext = () => {
    if (activeIndex < SECTIONS.length - 1) setActiveId(SECTIONS[activeIndex + 1].id);
  };
  const goPrev = () => {
    if (activeIndex > 0) setActiveId(SECTIONS[activeIndex - 1].id);
  };

  return (
    <div className="min-h-[calc(100vh-57px)] flex flex-col bg-black">
      {/* Header bar */}
      <div className="border-b border-gray-800 bg-gray-950 px-6 py-3 flex items-center gap-4 flex-shrink-0">
        <div className="flex items-center gap-2 flex-shrink-0">
          <Book size={15} className="text-green-400" />
          <span className="text-sm font-semibold text-white tracking-wide">User Guide</span>
          <span className="text-[10px] text-gray-600 font-mono">v{GUIDE_VERSION}</span>
        </div>
        <div className="flex-grow" />
        <ExportMenu />
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="w-56 flex-shrink-0 border-r border-gray-800 bg-gray-950/60 overflow-y-auto">
          <nav className="p-3 space-y-0.5">
            {SECTIONS.map((s, i) => (
              <button
                key={s.id}
                onClick={() => setActiveId(s.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-left text-sm transition-colors group ${
                  s.id === activeId
                    ? 'bg-green-900/30 text-green-400 border border-green-800/50'
                    : 'text-gray-400 hover:bg-gray-900 hover:text-gray-200'
                }`}
              >
                <span
                  className={`text-[10px] font-mono font-bold flex-shrink-0 w-4 ${
                    s.id === activeId ? 'text-green-500' : 'text-gray-600 group-hover:text-gray-500'
                  }`}
                >
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span className="leading-tight">{s.title}</span>
                {s.id === activeId && (
                  <ChevronRight size={12} className="ml-auto text-green-500 flex-shrink-0" />
                )}
              </button>
            ))}
          </nav>
        </aside>

        {/* Content */}
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-3xl mx-auto px-8 py-8">
            {/* Section header */}
            <div className="mb-6 pb-4 border-b border-gray-800">
              <div className="flex items-center gap-2 text-[10px] text-gray-600 uppercase tracking-widest font-semibold mb-1.5">
                <Shield size={10} className="text-green-700" />
                {GUIDE_TITLE}
                <span className="text-gray-700">›</span>
                <span className="text-gray-500">Section {activeIndex + 1} of {SECTIONS.length}</span>
              </div>
              <h2 className="text-xl font-bold text-white">{activeSection.title}</h2>
            </div>

            {/* Blocks */}
            <div>
              {activeSection.blocks.map((block, i) => (
                <GuideBlock key={i} block={block} />
              ))}
            </div>

            {/* Prev / Next navigation */}
            <div className="mt-10 pt-6 border-t border-gray-800 flex items-center justify-between">
              <button
                onClick={goPrev}
                disabled={activeIndex === 0}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm border border-gray-700 text-gray-400 hover:text-green-400 hover:border-green-500/40 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight size={14} className="rotate-180" />
                {activeIndex > 0 ? SECTIONS[activeIndex - 1].title : 'Previous'}
              </button>

              <span className="text-[10px] text-gray-600 font-mono">
                {activeIndex + 1} / {SECTIONS.length}
              </span>

              <button
                onClick={goNext}
                disabled={activeIndex === SECTIONS.length - 1}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm border border-gray-700 text-gray-400 hover:text-green-400 hover:border-green-500/40 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                {activeIndex < SECTIONS.length - 1 ? SECTIONS[activeIndex + 1].title : 'Next'}
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
