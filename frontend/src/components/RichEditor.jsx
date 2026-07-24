import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import Underline from '@tiptap/extension-underline';
import Link from '@tiptap/extension-link';
import Image from '@tiptap/extension-image';
import TextAlign from '@tiptap/extension-text-align';
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Bold, Italic, Underline as UnderlineIcon, Strikethrough,
  Link2, List, ListOrdered, AlignLeft, AlignCenter, AlignRight,
  Undo2, Redo2, Eraser, ImagePlus, Check, X as XIcon,
} from 'lucide-react';
import './RichEditor.css';

// ---------------------------------------------------------------------------
// Image extension extended with a configurable width attribute
// ---------------------------------------------------------------------------
const SizableImage = Image.extend({
  addAttributes() {
    return {
      ...this.parent?.(),
      width: {
        default: null,
        parseHTML: el => el.style.width || el.getAttribute('width') || null,
        renderHTML: attrs => {
          if (!attrs.width) return {};
          return { style: `width:${attrs.width};max-width:100%;height:auto;` };
        },
      },
    };
  },
});

// ---------------------------------------------------------------------------
// Small components
// ---------------------------------------------------------------------------
const Btn = ({ onClick, active, title, disabled, children }) => (
  <button
    type="button"
    onMouseDown={e => { e.preventDefault(); onClick(); }}
    disabled={disabled}
    title={title}
    className={`p-1.5 rounded transition-colors ${
      active
        ? 'bg-green-900/50 text-green-400'
        : 'text-gray-400 hover:text-white hover:bg-gray-700'
    } disabled:opacity-25 disabled:cursor-default`}
  >
    {children}
  </button>
);

const Sep = () => <div className="w-px bg-gray-700 self-stretch mx-0.5" />;

const WIDTH_PRESETS = ['25%', '50%', '75%', '100%'];

// ---------------------------------------------------------------------------
// Image panel (insert or edit)
// ---------------------------------------------------------------------------
const ImagePanel = ({ editor, mode, initialSrc, initialWidth, onClose }) => {
  const [url,   setUrl]         = useState(initialSrc   || '');
  const [preset, setPreset]     = useState(() => {
    if (!initialWidth || initialWidth === '100%') return '100%';
    return WIDTH_PRESETS.includes(initialWidth) ? initialWidth : 'custom';
  });
  const [custom, setCustom]     = useState(
    initialWidth && !WIDTH_PRESETS.includes(initialWidth) ? initialWidth : ''
  );
  const urlRef = useRef(null);

  useEffect(() => { urlRef.current?.focus(); }, []);

  const resolvedWidth = preset === 'custom' ? (custom.trim() || '100%') : preset;

  const apply = () => {
    if (!url.trim()) return;
    if (mode === 'insert') {
      editor.chain().focus().setImage({ src: url.trim(), width: resolvedWidth }).run();
    } else {
      editor.chain().focus().updateAttributes('image', { src: url.trim(), width: resolvedWidth }).run();
    }
    onClose();
  };

  const onKeyDown = e => {
    if (e.key === 'Enter') { e.preventDefault(); apply(); }
    if (e.key === 'Escape') onClose();
  };

  return (
    <div className="border-b border-gray-700 bg-gray-850 bg-gray-900 p-3 space-y-3" onKeyDown={onKeyDown}>
      {/* URL */}
      <div>
        <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1">
          Image URL
        </label>
        <input
          ref={urlRef}
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://example.com/image.png"
          className="w-full bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-green-500/50"
        />
      </div>

      {/* Width */}
      <div>
        <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1.5">
          Width
        </label>
        <div className="flex items-center gap-1.5 flex-wrap">
          {WIDTH_PRESETS.map(p => (
            <button
              key={p}
              type="button"
              onClick={() => setPreset(p)}
              className={`px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
                preset === p
                  ? 'bg-green-600 text-white'
                  : 'bg-gray-800 border border-gray-700 text-gray-400 hover:text-white'
              }`}
            >
              {p}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setPreset('custom')}
            className={`px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
              preset === 'custom'
                ? 'bg-green-600 text-white'
                : 'bg-gray-800 border border-gray-700 text-gray-400 hover:text-white'
            }`}
          >
            Custom
          </button>
          {preset === 'custom' && (
            <input
              value={custom}
              onChange={e => setCustom(e.target.value)}
              placeholder="e.g. 320px"
              autoFocus
              className="w-24 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-green-500/50"
            />
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={apply}
          disabled={!url.trim()}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-green-600 hover:bg-green-500 disabled:opacity-40 text-white text-xs font-bold transition-colors"
        >
          <Check size={12} />
          {mode === 'insert' ? 'Insert' : 'Update'}
        </button>
        <button
          type="button"
          onClick={onClose}
          className="flex items-center gap-1 px-2.5 py-1.5 rounded border border-gray-700 text-gray-400 hover:text-white text-xs transition-colors"
        >
          <XIcon size={12} /> Cancel
        </button>
        {mode === 'edit' && (
          <button
            type="button"
            onClick={() => {
              editor.chain().focus().deleteSelection().run();
              onClose();
            }}
            className="ml-auto text-xs text-red-500 hover:text-red-400 transition-colors"
          >
            Remove image
          </button>
        )}
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Main editor
// ---------------------------------------------------------------------------
export default function RichEditor({ value, onChange, placeholder = 'Enter message…' }) {
  const [imgPanel, setImgPanel] = useState(null); // null | { mode, src, width }

  const editor = useEditor({
    extensions: [
      StarterKit,
      Underline,
      Link.configure({ openOnClick: false, autolink: true }),
      SizableImage.configure({ allowBase64: false, inline: false }),
      TextAlign.configure({ types: ['heading', 'paragraph'] }),
    ],
    content: value || '',
    editorProps: {
      attributes: { 'data-placeholder': placeholder },
    },
    onUpdate: ({ editor }) => onChange(editor.getHTML()),
    // Close image panel on selection change away from image
    onSelectionUpdate: ({ editor }) => {
      if (imgPanel && !editor.isActive('image')) setImgPanel(null);
    },
  });

  useEffect(() => {
    if (!editor || editor.isDestroyed) return;
    if (value !== editor.getHTML()) editor.commands.setContent(value || '', false);
  }, [value]); // eslint-disable-line react-hooks/exhaustive-deps

  const setLink = useCallback(() => {
    if (!editor) return;
    const prev = editor.getAttributes('link').href || '';
    const url  = window.prompt('Enter URL', prev || 'https://');
    if (url === null) return;
    if (url === '') editor.chain().focus().extendMarkRange('link').unsetLink().run();
    else editor.chain().focus().extendMarkRange('link').setLink({ href: url }).run();
  }, [editor]);

  const handleImageBtn = useCallback(() => {
    if (!editor) return;
    if (editor.isActive('image')) {
      const attrs = editor.getAttributes('image');
      setImgPanel({ mode: 'edit', src: attrs.src || '', width: attrs.width || '100%' });
    } else {
      setImgPanel({ mode: 'insert', src: '', width: '100%' });
    }
  }, [editor]);

  if (!editor) return null;
  const e = editor;

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden focus-within:border-green-500/50 transition-colors bg-gray-900">
      {/* ── Toolbar ── */}
      <div className="flex flex-wrap items-center gap-0.5 px-2 py-1.5 bg-gray-900 border-b border-gray-700">

        <Btn title="Undo" onClick={() => e.chain().focus().undo().run()} disabled={!e.can().undo()}><Undo2 size={13} /></Btn>
        <Btn title="Redo" onClick={() => e.chain().focus().redo().run()} disabled={!e.can().redo()}><Redo2 size={13} /></Btn>

        <Sep />

        {[1, 2, 3].map(level => (
          <Btn key={level} title={`Heading ${level}`} active={e.isActive('heading', { level })}
               onClick={() => e.chain().focus().toggleHeading({ level }).run()}>
            <span className="text-[11px] font-bold leading-none">H{level}</span>
          </Btn>
        ))}

        <Sep />

        <Btn title="Bold"          active={e.isActive('bold')}      onClick={() => e.chain().focus().toggleBold().run()}>      <Bold          size={13} /></Btn>
        <Btn title="Italic"        active={e.isActive('italic')}    onClick={() => e.chain().focus().toggleItalic().run()}>    <Italic        size={13} /></Btn>
        <Btn title="Underline"     active={e.isActive('underline')} onClick={() => e.chain().focus().toggleUnderline().run()}> <UnderlineIcon size={13} /></Btn>
        <Btn title="Strikethrough" active={e.isActive('strike')}    onClick={() => e.chain().focus().toggleStrike().run()}>    <Strikethrough size={13} /></Btn>
        <Btn title="Link"          active={e.isActive('link')}      onClick={setLink}>                                         <Link2         size={13} /></Btn>
        <Btn title={e.isActive('image') ? 'Edit image' : 'Insert image'} active={e.isActive('image')} onClick={handleImageBtn}>
          <ImagePlus size={13} />
        </Btn>

        <Sep />

        <Btn title="Bullet list"  active={e.isActive('bulletList')}  onClick={() => e.chain().focus().toggleBulletList().run()}>  <List        size={13} /></Btn>
        <Btn title="Ordered list" active={e.isActive('orderedList')} onClick={() => e.chain().focus().toggleOrderedList().run()}> <ListOrdered size={13} /></Btn>
        <Btn title="Blockquote"   active={e.isActive('blockquote')}  onClick={() => e.chain().focus().toggleBlockquote().run()}>
          <span className="text-[13px] font-serif leading-none">&ldquo;</span>
        </Btn>

        <Sep />

        <Btn title="Align left"   active={e.isActive({ textAlign: 'left' })}   onClick={() => e.chain().focus().setTextAlign('left').run()}>   <AlignLeft   size={13} /></Btn>
        <Btn title="Align center" active={e.isActive({ textAlign: 'center' })} onClick={() => e.chain().focus().setTextAlign('center').run()}> <AlignCenter size={13} /></Btn>
        <Btn title="Align right"  active={e.isActive({ textAlign: 'right' })}  onClick={() => e.chain().focus().setTextAlign('right').run()}>  <AlignRight  size={13} /></Btn>

        <Sep />

        <Btn title="Clear formatting" onClick={() => e.chain().focus().clearNodes().unsetAllMarks().run()}>
          <Eraser size={13} />
        </Btn>
      </div>

      {/* ── Image panel ── */}
      {imgPanel && (
        <ImagePanel
          editor={editor}
          mode={imgPanel.mode}
          initialSrc={imgPanel.src}
          initialWidth={imgPanel.width}
          onClose={() => setImgPanel(null)}
        />
      )}

      {/* ── Editor content ── */}
      <EditorContent editor={editor} className="rich-editor-content" />
    </div>
  );
}
