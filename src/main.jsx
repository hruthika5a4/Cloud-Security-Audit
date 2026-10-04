import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { Toaster } from 'react-hot-toast'
import { AuthProvider } from './contexts/AuthContext.jsx'
import './index.css'
import App from './App.jsx'

window.onerror = function(msg, url, lineNo, columnNo, error) {
  console.error('GLOBAL ERROR:', msg, 'at', url, ':', lineNo, ':', columnNo, error);
  return false;
};

window.onunhandledrejection = function(event) {
  console.error('UNHANDLED REJECTION:', event.reason);
};

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <AuthProvider>
      <Toaster position="top-right" />
      <App />
    </AuthProvider>
  </StrictMode>,
)
