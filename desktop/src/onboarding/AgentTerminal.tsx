import { AppTerminal, focusTerminalIn } from '../ui/Terminal';

const DOM_ID = 'ob-term';

/** The onboarding's agent terminal. Leaving the step or finishing the onboarding only detaches
 *  it: the shell keeps running (the agent may already be working in it) and the dashboard's agents
 *  page lists it and reattaches. */
export function AgentTerminal({ name, tokenRef, asUser, onVerified, onFailed }: {
  name: string; tokenRef: string; asUser: string | null; onVerified(): void; onFailed(): void;
}) {
  return <AppTerminal domId={DOM_ID} name={name} source={{ kind: 'open', tokenRef, asUser }} onVerified={onVerified} onFailed={onFailed} />;
}

/** Focus the onboarding terminal's input. */
export function focusTerminal(): void {
  focusTerminalIn(DOM_ID);
}
