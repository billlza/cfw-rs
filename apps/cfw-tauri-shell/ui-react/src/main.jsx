import { createRoot } from "react-dom/client";
import { useState } from "react";

function App() {
  const [ticks, setTicks] = useState(0);

  return (
    <main className="shell">
      <h1 className="brand">Clash for Mac</h1>
      <p className="lede">
        Experimental React shell for Apple Silicon only. The production UI remains the legacy
        WebKit page under <code>ui/</code> until migration is complete — this page is not the
        default frontendDist.
      </p>
      <section className="panel">
        <h2>Parallel shell status</h2>
        <p>
          Platform lock: aarch64-apple-darwin. Core default: mihomo. Optional adapter: clash-rs.
          Network Extension and full App Sandbox are spike-only in 0.3.1.
        </p>
        <button type="button" className="badge" onClick={() => setTicks((n) => n + 1)}>
          React alive · clicks {ticks}
        </button>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
