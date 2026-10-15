import { createRoot } from 'react-dom/client';
import 'pretendard/dist/web/variable/pretendardvariable-dynamic-subset.css';
import '@fontsource/jetbrains-mono/latin-400.css';
import '@fontsource/jetbrains-mono/latin-500.css';
import '@fontsource/jetbrains-mono/latin-600.css';
import '@xterm/xterm/css/xterm.css';
import './styles/tokens.css';
import './styles/base.css';
import './styles/window.css';
import './styles/components.css';
import './styles/onboarding.css';
import './styles/terminal.css';
import './styles/dashboard.css';
import { App } from './App';

const root = document.getElementById('root');
if (root) createRoot(root).render(<App />);
