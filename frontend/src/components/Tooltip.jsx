import React, { useState, useRef, useCallback, useLayoutEffect } from 'react';
import { createPortal } from 'react-dom';
import { Info } from 'lucide-react';

/**
 * Tooltip — renders into document.body via a portal and clamps to viewport edges.
 *
 * Props:
 *   content    string | ReactNode  — tooltip body text
 *   position   'top'|'bottom'|'left'|'right'  preferred side (default: 'top')
 *   maxWidth   number  px max-width of the tooltip box (default: 260)
 *   delay      number  ms before tooltip appears (default: 120)
 */
export const Tooltip = ({ children, content, position = 'top', maxWidth = 260, delay = 120 }) => {
  const [visible, setVisible] = useState(false);
  const timerRef = useRef(null);
  const triggerRef = useRef(null);
  const tooltipRef = useRef(null);

  const updatePosition = useCallback(() => {
    if (!triggerRef.current || !tooltipRef.current) return;
    const tr = triggerRef.current.getBoundingClientRect();
    const tt = tooltipRef.current.getBoundingClientRect();
    const gap = 8;
    const pad = 6;

    let top, left;
    if (position === 'bottom') {
      top = tr.bottom + gap;
      left = tr.left + tr.width / 2 - tt.width / 2;
    } else if (position === 'left') {
      top = tr.top + tr.height / 2 - tt.height / 2;
      left = tr.left - tt.width - gap;
    } else if (position === 'right') {
      top = tr.top + tr.height / 2 - tt.height / 2;
      left = tr.right + gap;
    } else {
      // top (default)
      top = tr.top - tt.height - gap;
      left = tr.left + tr.width / 2 - tt.width / 2;
    }

    // Clamp to viewport so the tooltip never goes off-screen
    left = Math.max(pad, Math.min(left, window.innerWidth - tt.width - pad));
    top  = Math.max(pad, Math.min(top,  window.innerHeight - tt.height - pad));

    tooltipRef.current.style.top  = `${top}px`;
    tooltipRef.current.style.left = `${left}px`;
    tooltipRef.current.style.opacity = '1';
  }, [position]);

  const show = useCallback(() => {
    timerRef.current = setTimeout(() => setVisible(true), delay);
  }, [delay]);

  const hide = useCallback(() => {
    clearTimeout(timerRef.current);
    setVisible(false);
  }, []);

  // Fire synchronously after DOM update so we can read real dimensions
  // before the browser paints — no visible flash.
  useLayoutEffect(() => {
    if (visible) updatePosition();
  }, [visible, updatePosition]);

  if (!content) return <>{children}</>;

  return (
    <>
      <span
        ref={triggerRef}
        className="inline-flex items-center"
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
      >
        {children}
      </span>

      {visible && createPortal(
        <div
          ref={tooltipRef}
          role="tooltip"
          className="fixed z-[9999] pointer-events-none"
          style={{ top: -9999, left: -9999, opacity: 0, width: maxWidth }}
        >
          <div className="bg-gray-900 border border-gray-600 text-gray-200 text-xs rounded-lg px-3 py-2 shadow-2xl leading-relaxed whitespace-normal">
            {content}
          </div>
        </div>,
        document.body,
      )}
    </>
  );
};

/**
 * InfoTip — a standalone ⓘ icon that shows a tooltip on hover.
 * Drop it next to any label.
 */
export const InfoTip = ({ content, position = 'top', size = 11, className = '' }) => (
  <Tooltip content={content} position={position}>
    <Info
      size={size}
      className={`text-gray-600 hover:text-gray-400 cursor-help flex-shrink-0 transition-colors ${className}`}
    />
  </Tooltip>
);
