import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { t } from '../copy';
import { call, outputChannel, toIpcError } from '../ipc/client';
import { useApp } from '../ui/context';

const THEME = {
  background: '#05050a', foreground: '#bfbfcc', cursor: '#8fb0ff', cursorAccent: '#05050a',
  selectionBackground: 'rgba(122, 124, 255, 0.35)',
  black: '#2b2b33', brightBlack: '#575768', red: '#ff7a93', brightRed: '#ff9aae', green: '#9fd8b0', brightGreen: '#b8e6c5',
  yellow: '#f3c36f', brightYellow: '#f7d493', blue: '#5b8cff', brightBlue: '#8fb0ff', magenta: '#9a6bff', brightMagenta: '#c4a8ff',
  cyan: '#7fb8ff', brightCyan: '#a9cfff', white: '#bfbfcc', brightWhite: '#f2f2f7',
};
// strip CSI/OSC sequences before looking for the list-connections answer
const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[@-_]/g;
const VERIFIED = /"connections"\s*:/;

/** The in-app terminal (docs/desktop-app.md §4.4). The core starts the user's shell with the relay
 *  address and the token in its environment; nothing secret is typed or shown here. Suggested
 *  commands are typed into the prompt without a newline; the user runs them with Enter. */
export function AgentTerminal({ name, tokenRef, asUser, onVerified, onFailed }: {
  name: string; tokenRef: string; asUser: string | null; onVerified(): void; onFailed(): void;
}) {
  const { motionOn, toast } = useApp();
  const host = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const idRef = useRef<string | null>(null);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [used, setUsed] = useState<Set<number>>(new Set());
  const [pending, setPending] = useState<number | null>(null);
  const [altOpen, setAltOpen] = useState(false);
  const [closed, setClosed] = useState(false);
  const verified = useRef(false);
  const cb = useRef({ onVerified, onFailed });
  cb.current = { onVerified, onFailed };

  const write = (data: string) => {
    const id = idRef.current;
    if (!id) return;
    call('terminal_write', { terminal_id: id, data }).catch((e) => {
      if (toIpcError(e).reason === 'terminal_unknown') setClosed(true);
    });
  };

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    let disposed = false;
    const term = new Terminal({
      fontFamily: '"JetBrains Mono", "Pretendard Variable", Menlo, monospace', fontSize: 12, lineHeight: 1.45,
      cursorBlink: motionOn, cursorStyle: 'block', allowTransparency: false, scrollback: 2000, theme: THEME,
      convertEol: false,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    termRef.current = term;
    try { fit.fit(); } catch { /* not laid out yet */ }

    let tail = '', firstOutput = true, autoTyped = false, quiet: ReturnType<typeof setTimeout> | null = null;
    let list: string[] = [];
    const typeFirst = () => {
      if (autoTyped || disposed || !list.length) return;
      autoTyped = true;
      write(list[0] ?? '');
      setUsed(new Set([0])); setPending(0);
    };
    const onData = (data: string) => {
      if (disposed) return;
      term.write(data);
      if (firstOutput) { firstOutput = false; }
      if (quiet) clearTimeout(quiet);
      quiet = setTimeout(typeFirst, 250);
      if (!verified.current) {
        tail = (tail + data.replace(ANSI, '')).slice(-4096);
        if (VERIFIED.test(tail)) { verified.current = true; cb.current.onVerified(); }
      }
    };
    const sub = term.onData((d) => { write(d); if (d.includes('\r')) setPending(null); });
    const subR = term.onResize(({ cols, rows }) => {
      const id = idRef.current;
      if (id) call('terminal_resize', { terminal_id: id, cols, rows }).catch(() => undefined);
    });

    const args: { token_ref: string; on_data: unknown; as_user?: string } = { token_ref: tokenRef, on_data: outputChannel(onData) };
    if (asUser) args.as_user = asUser;
    call('terminal_open', args).then(
      (r) => {
        if (disposed) { call('terminal_close', { terminal_id: r.terminal_id }).catch(() => undefined); return; }
        idRef.current = r.terminal_id;
        list = r.suggestions.slice(0, 4);
        setSuggestions(list);
        call('terminal_resize', { terminal_id: r.terminal_id, cols: term.cols, rows: term.rows }).catch(() => undefined);
        if (!firstOutput) { if (quiet) clearTimeout(quiet); quiet = setTimeout(typeFirst, 250); }
      },
      () => { if (!disposed) { toast(t('term.err'), 'warn'); cb.current.onFailed(); } },
    );

    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(() => { try { fit.fit(); } catch { /* hidden */ } }) : null;
    ro?.observe(el);
    return () => {
      disposed = true;
      if (quiet) clearTimeout(quiet);
      ro?.disconnect(); sub.dispose(); subR.dispose();
      const id = idRef.current;
      idRef.current = null;
      if (id) call('terminal_close', { terminal_id: id }).catch(() => undefined);
      term.dispose();
      termRef.current = null;
    };
    // the terminal lives as long as this component; props are read once on open
  }, []);

  useEffect(() => { if (termRef.current) termRef.current.options.cursorBlink = motionOn; }, [motionOn]);

  const typeSuggestion = (i: number) => {
    const cmd = suggestions[i];
    if (!cmd) return;
    write(cmd);
    setUsed((u) => new Set(u).add(i)); setPending(i);
    termRef.current?.focus();
  };

  const copyToken = async () => {
    try {
      const r = await call('onetime_copy', { ref: tokenRef });
      if (r.copied) toast(t('toast.copy.token'));
    } catch {
      toast(t('error.generic'), 'warn');
    }
  };

  return (
    <div className="term" id="ob-term">
      <div className="term-bar">
        <i /><i /><i />
        <span className="tt">{t('term.title', { name })}</span>
        <button className="icon-btn" type="button" aria-expanded={altOpen} aria-controls="ob-term-alt" onClick={() => setAltOpen(!altOpen)}>{t('term.other')}</button>
      </div>
      <div className="term-cmt"># {t('term.comment')}</div>
      <div className="term-body" ref={host} role="group" aria-label={t('term.aria')} />
      {closed && <div className="term-note" role="status">{t('term.closed')}</div>}
      {suggestions.length > 0 && (
        <div className="term-suggest" role="group" aria-labelledby="ob-term-suggest">
          <span className="lbl" id="ob-term-suggest">{t('term.suggest')}</span>
          {suggestions.map((cmd, i) => (
            <button key={cmd} className={'chip' + (used.has(i) ? ' used' : '') + (i === pending ? ' pending' : '')} type="button" title={cmd}
              aria-label={t('term.chip.aria', { cmd })} onClick={() => typeSuggestion(i)}>
              <span className="cmd">{cmd}</span>
              {i === pending && <span className="kbd" aria-hidden="true">{t('term.run')} ↵</span>}
            </button>
          ))}
        </div>
      )}
      <div className="term-alt" id="ob-term-alt" hidden={!altOpen}>
        <button className="btn btn-text btn-sm" type="button" onClick={() => void copyToken()}>{t('term.copy')}</button>
      </div>
    </div>
  );
}

/** Focus the terminal's input (xterm keeps a hidden textarea inside the body). */
export function focusTerminal(): void {
  document.querySelector<HTMLTextAreaElement>('#ob-term .xterm-helper-textarea')?.focus();
}
