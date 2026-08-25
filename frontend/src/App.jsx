import { useState } from 'react';
import Landing from './Landing.jsx';
import CreateSecret from './CreateSecret.jsx';
import ViewSecret from './ViewSecret.jsx';

function App() {
  const isViewRoute = window.location.hash.startsWith('#/view/');

  const [phase, setPhase] = useState('landing'); // 'landing' | 'transitioning' | 'create'
  const [scrollTarget, setScrollTarget] = useState(null);

  function enterCreate(targetAnchor) {
    setScrollTarget(targetAnchor || null);
    setPhase('transitioning');
    // Matches --transition-duration in index.css.
    window.setTimeout(() => setPhase('create'), 750);
  }

  // Recipients opening a #/view/... link always land directly on the reveal
  // page — unchanged from the original behavior, they never see the
  // sender's landing page.
  if (isViewRoute) {
    return <ViewSecret />;
  }

  return (
    <>
      {phase !== 'create' && <Landing onEnter={enterCreate} />}
      {phase === 'transitioning' && <div className="dl-transition-overlay" aria-hidden="true" />}
      {phase === 'create' && <CreateSecret initialScrollTarget={scrollTarget} />}
    </>
  );
}

export default App;
