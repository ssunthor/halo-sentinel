import React, { useState, useRef, useCallback } from 'react';
import { X } from 'lucide-react';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * TagInput — pill-style email address list editor.
 *
 * Props:
 *   value       string[]   current list of addresses
 *   onChange    fn(string[]) called on every add/remove
 *   placeholder string     input placeholder text
 *   id          string     input element id (for label association)
 */
export default function TagInput({ value = [], onChange, placeholder = 'Add address…', id }) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const inputRef = useRef(null);

  const add = useCallback((raw) => {
    const addr = raw.trim().toLowerCase();
    if (!addr) return;
    if (!EMAIL_RE.test(addr)) {
      setError(`"${addr}" is not a valid email address.`);
      return;
    }
    if (value.includes(addr)) {
      setError(`"${addr}" is already in the list.`);
      return;
    }
    onChange([...value, addr]);
    setDraft('');
    setError('');
  }, [value, onChange]);

  const remove = useCallback((addr) => {
    onChange(value.filter(a => a !== addr));
  }, [value, onChange]);

  const onKeyDown = useCallback((e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      add(draft);
    } else if (e.key === 'Backspace' && !draft && value.length) {
      remove(value[value.length - 1]);
    }
  }, [draft, add, remove, value]);

  const onBlur = useCallback(() => {
    if (draft.trim()) add(draft);
  }, [draft, add]);

  return (
    <div>
      <div
        className="min-h-[42px] flex flex-wrap items-center gap-1.5 px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg cursor-text focus-within:border-green-500/50 transition-colors"
        onClick={() => inputRef.current?.focus()}
      >
        {value.map(addr => (
          <span
            key={addr}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-green-900/30 border border-green-500/40 text-green-300 text-xs font-mono"
          >
            {addr}
            <button
              type="button"
              onClick={e => { e.stopPropagation(); remove(addr); }}
              className="text-green-500 hover:text-white transition-colors flex-shrink-0"
              aria-label={`Remove ${addr}`}
            >
              <X size={11} />
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          id={id}
          type="text"
          value={draft}
          onChange={e => { setDraft(e.target.value); setError(''); }}
          onKeyDown={onKeyDown}
          onBlur={onBlur}
          placeholder={value.length === 0 ? placeholder : ''}
          className="flex-grow min-w-[180px] bg-transparent text-sm text-white placeholder-gray-600 outline-none py-0.5"
        />
      </div>
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
      <p className="mt-1 text-[10px] text-gray-600">Press Enter or comma to add · Backspace to remove last</p>
    </div>
  );
}
