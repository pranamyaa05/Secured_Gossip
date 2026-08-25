import privacyImage from './assets/privacy.png';

function HeroRibbon() {
  return (
    <svg viewBox="0 0 900 500" className="hero-ribbon" preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id="ribbonGradient" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="var(--mint)" />
          <stop offset="55%" stopColor="var(--lavender)" />
          <stop offset="100%" stopColor="var(--peach)" />
        </linearGradient>
      </defs>
      <path d="M -50 260 C 150 180, 280 340, 450 240 C 600 160, 750 300, 950 200"
        stroke="url(#ribbonGradient)" strokeWidth="46" opacity="0.35" fill="none" strokeLinecap="round" />
      <path d="M -50 320 C 180 260, 300 400, 480 300 C 650 220, 780 360, 950 260"
        stroke="var(--lavender)" strokeWidth="20" opacity="0.25" fill="none" strokeLinecap="round" />
      <path d="M -50 200 C 160 140, 320 260, 470 180 C 620 100, 760 220, 950 140"
        stroke="var(--mint)" strokeWidth="12" opacity="0.28" fill="none" strokeLinecap="round" />
    </svg>
  );
}

function Landing({ onEnter }) {
  return (
    <div className="landing">
      <header className="landing-header">
        <span className="wordmark">Secured_Gossip</span>
      </header>

      <div className="landing-content">
        <section className="landing-hero">
          <HeroRibbon />
          <h1 className="landing-headline">
            <span className="headline-line">What&rsquo;s said</span>
            <span className="headline-line headline-line-accent">between us</span>
            <span className="headline-line">stays between us.</span>
          </h1>
          <p className="landing-subtext">
            Secured_Gossip encrypts your message in your browser before it ever leaves your
            device. Share a link. Add a PIN if you like. Watch it disappear once it&rsquo;s read.
          </p>
          <div className="landing-cta-row">
            <button className="btn btn-primary-dark" onClick={() => onEnter(null)}>Create a Secret</button>
            <button className="btn btn-ghost-dark" onClick={() => onEnter('how-it-works')}>How it works</button>
          </div>
        </section>

        <div className="landing-image-container">
          <img
            src={privacyImage}
            alt="Secured Gossip Privacy"
            className="landing-image"
          />
        </div>
      </div>
    </div>
  );
}

export default Landing;
