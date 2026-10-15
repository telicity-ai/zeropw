import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { t } from '../copy';
import { call, outputChannel } from '../ipc/client';
import { useApp } from './context';
import { TerminalInput } from './terminalInput';

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
/** How long the "input was dropped" notice stays after input goes through again. */
const DROPPED_NOTE_MS = 6000;

/** Open a new shell for a caller token, or reattach to one that is still running. */
export type TerminalSource =
  | { kind: 'open'; tokenRef: string; asUser: string | null }
  | { kind: 'attach'; terminalId: string };

/** The in-app terminal (docs/desktop-app.md §4.4). The core starts the user's shell with the relay
 *  address and the token in its environment; nothing secret is typed or shown here. Suggested
 *  commands are typed into the prompt without a newline; the user runs them with Enter.
 *  Unmounting only detaches: the shell keeps running so the agent keeps working, and the agents
 *  page reattaches with `terminal_attach` (the core replays its buffered output). */
export function AppTerminal({ domId, name, source, onOpened, onVerified, onFailed, onClosed }: {
  domId: string; name: string; source: TerminalSource;
  onOpened?(terminalId: string): void; onVerified?(): void; onFailed?(): void; onClosed?(): void;
}) {
  const { motionOn, toast, announce } = useApp();
  const host = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const idRef = useRef<string | null>(null);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [used, setUsed] = useState<Set<number>>(new Set());
  const [pending, setPending] = useState<number | null>(null);
  const [altOpen, setAltOpen] = useState(false);
  const [closed, setClosed] = useState(false);
  const [dropped, setDropped] = useState(false);
  const [tokenGone, setTokenGone] = useState(false);
  const verified = useRef(false);
  const cb = useRef({ onOpened, onVerified, onFailed, onClosed });
  cb.current = { onOpened, onVerified, onFailed, onClosed };
  const tokenRef = source.kind === 'open' ? source.tokenRef : null;
  const input = useRef<TerminalInput | null>(null);
  const droppedTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const droppedShown = useRef(false);

  // input goes out in order; input the program did not read is dropped and said so (./terminalInput.ts)
  const write = (data: string) => { input.current?.write(data); };
  const inputFor = (terminalId: string) => new TerminalInput((data) => call('terminal_write', { terminal_id: terminalId, data }), {
    busy: () => {
      if (droppedTimer.current) clearTimeout(droppedTimer.current);
      droppedTimer.current = null;
      if (!droppedShown.current) announce(t('term.busy'));
      droppedShown.current = true;
      setDropped(true);
    },
    // keep the notice a moment after input flows again, so it is not missed
    accepted: () => {
      if (droppedTimer.current) clearTimeout(droppedTimer.current);
      droppedTimer.current = setTimeout(() => { droppedShown.current = false; setDropped(false); }, DROPPED_NOTE_MS);
    },
    gone: () => { setClosed(true); cb.current.onClosed?.(); },
  });

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

    // a fresh shell gets its first suggestion typed in once the prompt settles; a reattached one does not
    const autoType = source.kind === 'open';
    let firstOutput = true, autoTyped = !autoType, quiet: ReturnType<typeof setTimeout> | null = null, tail = '';
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
      firstOutput = false;
      if (quiet) clearTimeout(quiet);
      quiet = setTimeout(typeFirst, 250);
      if (!verified.current) {
        tail = (tail + data.replace(ANSI, '')).slice(-4096);
        if (VERIFIED.test(tail)) { verified.current = true; cb.current.onVerified?.(); }
      }
    };
    const sub = term.onData((d) => { write(d); if (d.includes('\r')) setPending(null); });
    const subR = term.onResize(({ cols, rows }) => {
      const id = idRef.current;
      if (id) call('terminal_resize', { terminal_id: id, cols, rows }).catch(() => undefined);
    });

    const channel = outputChannel(onData);
    const opened = source.kind === 'open'
      ? call('terminal_open', { token_ref: source.tokenRef, on_data: channel, ...(source.asUser ? { as_user: source.asUser } : {}) })
      : call('terminal_attach', { terminal_id: source.terminalId, on_data: channel });
    opened.then(
      (r) => {
        if (disposed) return;   // detached before the core answered; the shell keeps running
        idRef.current = r.terminal_id;
        input.current = inputFor(r.terminal_id);
        list = r.suggestions.slice(0, 4);
        setSuggestions(list);
        call('terminal_resize', { terminal_id: r.terminal_id, cols: term.cols, rows: term.rows }).catch(() => undefined);
        if (!firstOutput) { if (quiet) clearTimeout(quiet); quiet = setTimeout(typeFirst, 250); }
        cb.current.onOpened?.(r.terminal_id);
      },
      () => { if (!disposed) { toast(t('term.err'), 'warn'); cb.current.onFailed?.(); } },
    );

    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(() => { try { fit.fit(); } catch { /* hidden */ } }) : null;
    ro?.observe(el);
    return () => {
      disposed = true;
      if (quiet) clearTimeout(quiet);
      ro?.disconnect(); sub.dispose(); subR.dispose();
      idRef.current = null;
      input.current?.dispose(); input.current = null;
      if (droppedTimer.current) clearTimeout(droppedTimer.current);
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

  // copying hands the token over once: the core forgets it after writing the clipboard
  const copyToken = async () => {
    if (!tokenRef || tokenGone) return;
    try {
      const r = await call('onetime_copy', { ref: tokenRef });
      if (r.copied) { toast(t('toast.copy.token')); setTokenGone(true); }
    } catch {
      setTokenGone(true);
      toast(t('error.generic'), 'warn');
    }
  };

  return (
    <div className="term" id={domId}>
      <div className="term-bar">
        <i /><i /><i />
        <span className="tt">{t('term.title', { name })}</span>
        {tokenRef && (
          <button className="icon-btn" type="button" aria-expanded={altOpen} aria-controls={`${domId}-alt`} onClick={() => setAltOpen(!altOpen)}>{t('term.other')}</button>
        )}
      </div>
      <div className="term-cmt"># {t('term.comment')}</div>
      <div className="term-body" ref={host} role="group" aria-label={t('term.aria')} />
      {closed && <div className="term-note" role="status">{t('term.closed')}</div>}
      {!closed && dropped && <div className="term-note warn">{t('term.busy')}</div>}
      {suggestions.length > 0 && (
        <div className="term-suggest" role="group" aria-labelledby={`${domId}-suggest`}>
          <span className="lbl" id={`${domId}-suggest`}>{t('term.suggest')}</span>
          {suggestions.map((cmd, i) => (
            <button key={cmd} className={'chip' + (used.has(i) ? ' used' : '') + (i === pending ? ' pending' : '')} type="button" title={cmd}
              aria-label={t('term.chip.aria', { cmd })} onClick={() => typeSuggestion(i)}>
              <span className="cmd">{cmd}</span>
              {i === pending && <span className="kbd" aria-hidden="true">{t('term.run')} ↵</span>}
            </button>
          ))}
        </div>
      )}
      {tokenRef && (
        <div className="term-alt" id={`${domId}-alt`} hidden={!altOpen}>
          <button className="btn btn-text btn-sm" type="button" aria-disabled={tokenGone} onClick={() => void copyToken()}>{t('term.copy')}</button>
        </div>
      )}
    </div>
  );
}

/** Focus a terminal's input (xterm keeps a hidden textarea inside the body). */
export function focusTerminalIn(domId: string): void {
  document.querySelector<HTMLTextAreaElement>(`#${CSS.escape(domId)} .xterm-helper-textarea`)?.focus();
}
