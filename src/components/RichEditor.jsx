import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import Underline from '@tiptap/extension-underline';
import Link from '@tiptap/extension-link';
import Image from '@tiptap/extension-image';
import TextAlign from '@tiptap/extension-text-align';
import { useEffect, useCallback } from 'react';
import {
  Bold, Italic, Underline as UnderlineIcon, Strikethrough,
  Link2, List, ListOrdered, AlignLeft, AlignCenter, AlignRight,
  Undo2, Redo2, Eraser, ImagePlus,
} from 'lucide-react';
import './RichEditor.css';

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

export default function RichEditor({ value, onChange, placeholder = 'Enter message…' }) {
  const editor = useEditor({
    extensions: [
      StarterKit,
      Underline,
      Link.configure({ openOnClick: false, autolink: true }),
      Image.configure({ allowBase64: false, inline: false }),
      TextAlign.configure({ types: ['heading', 'paragraph'] }),
    ],
    content: value || '',
    editorProps: {
      attributes: { 'data-placeholder': placeholder },
    },
    onUpdate: ({ editor }) => onChange(editor.getHTML()),
  });

  // Sync when value changes externally (e.g. form load)
  useEffect(() => {
    if (!editor || editor.isDestroyed) return;
    if (value !== editor.getHTML()) {
      editor.commands.setContent(value || '', false);
    }
  }, [value]); // eslint-disable-line react-hooks/exhaustive-deps

  const insertImage = useCallback(() => {
    if (!editor) return;
    const url = window.prompt('Image URL', 'https://');
    if (!url || !url.trim()) return;
    editor.chain().focus().setImage({ src: url.trim() }).run();
  }, [editor]);

  const setLink = useCallback(() => {
    if (!editor) return;
    const prev = editor.getAttributes('link').href || '';
    const url  = window.prompt('Enter URL', prev || 'https://');
    if (url === null) return;
    if (url === '') {
      editor.chain().focus().extendMarkRange('link').unsetLink().run();
    } else {
      editor.chain().focus().extendMarkRange('link').setLink({ href: url }).run();
    }
  }, [editor]);

  if (!editor) return null;

  const e = editor;

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden focus-within:border-green-500/50 transition-colors bg-gray-900">
      {/* ── Toolbar ── */}
      <div className="flex flex-wrap items-center gap-0.5 px-2 py-1.5 bg-gray-900 border-b border-gray-700">

        <Btn title="Undo" onClick={() => e.chain().focus().undo().run()} disabled={!e.can().undo()}>
          <Undo2 size={13} />
        </Btn>
        <Btn title="Redo" onClick={() => e.chain().focus().redo().run()} disabled={!e.can().redo()}>
          <Redo2 size={13} />
        </Btn>

        <Sep />

        {[1, 2, 3].map(level => (
          <Btn
            key={level}
            title={`Heading ${level}`}
            active={e.isActive('heading', { level })}
            onClick={() => e.chain().focus().toggleHeading({ level }).run()}
          >
            <span className="text-[11px] font-bold leading-none">H{level}</span>
          </Btn>
        ))}

        <Sep />

        <Btn title="Bold"          active={e.isActive('bold')}      onClick={() => e.chain().focus().toggleBold().run()}>      <Bold          size={13} /></Btn>
        <Btn title="Italic"        active={e.isActive('italic')}    onClick={() => e.chain().focus().toggleItalic().run()}>    <Italic        size={13} /></Btn>
        <Btn title="Underline"     active={e.isActive('underline')} onClick={() => e.chain().focus().toggleUnderline().run()}> <UnderlineIcon size={13} /></Btn>
        <Btn title="Strikethrough" active={e.isActive('strike')}    onClick={() => e.chain().focus().toggleStrike().run()}>    <Strikethrough size={13} /></Btn>
        <Btn title="Link"         active={e.isActive('link')} onClick={setLink}>      <Link2     size={13} /></Btn>
        <Btn title="Insert image"                             onClick={insertImage}> <ImagePlus size={13} /></Btn>

        <Sep />

        <Btn title="Bullet list"   active={e.isActive('bulletList')}  onClick={() => e.chain().focus().toggleBulletList().run()}>  <List        size={13} /></Btn>
        <Btn title="Ordered list"  active={e.isActive('orderedList')} onClick={() => e.chain().focus().toggleOrderedList().run()}> <ListOrdered size={13} /></Btn>
        <Btn title="Blockquote"    active={e.isActive('blockquote')}  onClick={() => e.chain().focus().toggleBlockquote().run()}>
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

      {/* ── Editor content ── */}
      <EditorContent editor={editor} className="rich-editor-content" />
    </div>
  );
}
