// A data channel gathers ICE addresses without asking for a camera or mic.
// This observes this WebView only; it cannot certify other browsers/apps.
export function probeWebRtc({ PeerConnection = globalThis.RTCPeerConnection, signal, timeoutMs = 8000 } = {}) {
  if (typeof PeerConnection !== "function") return Promise.resolve({ status: "unsupported", addresses: [] });
  if (signal?.aborted) return Promise.resolve({ status: "failed", reason: "cancelled", addresses: [] });
  return new Promise((resolve) => {
    let peer;
    let channel;
    let timer;
    let settled = false;
    const addresses = new Set();
    const finish = (status, reason) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (peer) {
        peer.onicecandidate = null;
        peer.onicecandidateerror = null;
        channel?.close();
        peer.close();
      }
      resolve({ status, ...(reason ? { reason } : {}), addresses: [...addresses] });
    };
    const abort = () => finish("failed", "cancelled");
    try {
      peer = new PeerConnection({ iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }], iceCandidatePoolSize: 0 });
      peer.onicecandidate = ({ candidate }) => {
        if (!candidate) {
          finish(addresses.size ? "observed" : "failed", addresses.size ? undefined : "no_udp_candidate");
          return;
        }
        // Host/mDNS candidates are local interfaces, not public egress proof.
        if (candidate.type === "srflx" && candidate.protocol === "udp" && typeof candidate.address === "string"
            && candidate.address.length <= 45 && /^[0-9a-f:.]+$/iu.test(candidate.address)) {
          addresses.add(candidate.address);
          if (addresses.size > 8) finish("failed", "response_too_large");
        }
      };
      // Individual IPv6/STUN candidate errors do not cancel an IPv4 candidate.
      // The bounded final result still fails if no srflx address was obtained.
      timer = setTimeout(() => finish("failed", "timeout"), timeoutMs);
      signal?.addEventListener("abort", abort, { once: true });
      channel = peer.createDataChannel("connection-diagnostic");
      peer.createOffer().then((offer) => {
        if (!settled) return peer.setLocalDescription(offer);
      }).catch(() => finish("failed", "webrtc_failed"));
    } catch {
      finish("failed", "webrtc_failed");
    }
  });
}
