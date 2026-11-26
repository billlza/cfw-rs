// The node the providers session health-checks: an HTTP proxy stand-in that
// answers only the health check the session's profile declares, and dials
// nothing. It is started with the address to listen on (an IPv4 address of
// this machine), the check's http URL, a receipt path it creates and a
// deadline in seconds. It listens on a port the system picks.
//
// A connection must ask, in turn, for
//   CONNECT <url host>:<url port> HTTP/1.1
// which is answered 200, and then, through the tunnel, for
//   HEAD|GET <url path> HTTP/1.1  with  Host: <url host>[:<url port>]
// which is answered 204 before the connection closes. Anything else is
// refused with a 4xx status, or closed when its request head exceeds 8 KiB
// or stays incomplete for 10 seconds.
//
// The receipt is JSON lines, written in order: listening {address, port};
// answered {method, path, host} per check answered; refused {reason} per
// connection refused; then closed {answered, refused} when standard input
// ends (exit 0), or deadline when the deadline passes first (exit 3).
// Invalid arguments or a failed listen exit 2 without a listening line.
import { appendFileSync, writeFileSync } from 'node:fs';
import { createServer, isIPv4 } from 'node:net';
import { isAbsolute } from 'node:path';

const HEAD_LIMIT = 8192;
const IDLE_MS = 10000;
const CONCURRENT_LIMIT = 16;
const TOTAL_LIMIT = 256;

function fail(message) {
  process.stderr.write(`provider stand-in: ${message}\n`);
  process.exit(2);
}

const [address, link, receipt, deadlineText, ...extra] = process.argv.slice(2);
if (extra.length !== 0 || !isIPv4(address ?? '')) fail('usage: <IPv4 address> <http URL> <receipt> <deadline seconds>');
let target;
try { target = new URL(link); } catch { fail('the health-check URL is invalid'); }
if (target.protocol !== 'http:' || !target.hostname || target.username || target.password || target.search ||
    target.hash || target.port === '0' || target.href !== link) {
  fail('the health-check URL must be a plain http URL without credentials, query or fragment');
}
const port = target.port || '80';
const connectLine = `CONNECT ${target.hostname}:${port} HTTP/1.1`;
const hosts = new Set([target.hostname, `${target.hostname}:${port}`]);
if (typeof receipt !== 'string' || !isAbsolute(receipt)) fail('the receipt path must be absolute');
const deadline = Number(deadlineText);
if (!/^[1-9][0-9]{0,3}$/.test(deadlineText ?? '') || deadline > 3600) fail('the deadline must be 1..3600 seconds');
try { writeFileSync(receipt, '', { flag: 'wx' }); } catch (error) { fail(`the receipt cannot be created: ${error.code}`); }

const record = event => appendFileSync(receipt, `${JSON.stringify(event)}\n`);
const sockets = new Set();
let answered = 0;
let refused = 0;
let accepted = 0;
let finished = false;

function refuse(socket, reason, status) {
  refused += 1;
  record({ event: 'refused', reason });
  if (status) socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  else socket.destroy();
}

// Reads one request head from the bytes buffered so far; the rest stays.
function takeHead(state) {
  const end = state.buffer.indexOf('\r\n\r\n');
  if (end < 0) return state.buffer.length > HEAD_LIMIT ? false : null;
  if (end > HEAD_LIMIT) return false;
  const lines = state.buffer.subarray(0, end).toString('latin1').split('\r\n');
  state.buffer = state.buffer.subarray(end + 4);
  return lines;
}

function hostHeader(lines) {
  const values = lines.slice(1).filter(line => /^host:/i.test(line)).map(line => line.slice(5).trim());
  return values.length === 1 ? values[0] : null;
}

function serve(socket) {
  accepted += 1;
  if (accepted > TOTAL_LIMIT) { refuse(socket, 'connection bound'); return; }
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
  socket.on('error', () => {});
  const state = { buffer: Buffer.alloc(0), tunneled: false, done: false };
  // A connection already answered or refused only waits for its peer to close.
  socket.setTimeout(IDLE_MS, () => {
    if (state.done) { socket.destroy(); return; }
    state.done = true;
    refuse(socket, 'incomplete request');
  });
  socket.on('data', chunk => {
    if (state.done) return;
    state.buffer = Buffer.concat([state.buffer, chunk]);
    for (;;) {
      const lines = takeHead(state);
      if (lines === null) return;
      if (lines === false) { state.done = true; refuse(socket, 'request head too large', '431 Request Header Fields Too Large'); return; }
      if (!state.tunneled) {
        if (lines[0] !== connectLine) { state.done = true; refuse(socket, `unexpected proxy request: ${lines[0].slice(0, 120)}`, '405 Method Not Allowed'); return; }
        state.tunneled = true;
        socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
        continue;
      }
      state.done = true;
      const [method, path, version] = lines[0].split(' ');
      const host = hostHeader(lines);
      if (!['HEAD', 'GET'].includes(method) || path !== target.pathname || version !== 'HTTP/1.1' || !hosts.has(host)) {
        refuse(socket, `unexpected checked request: ${lines[0].slice(0, 120)}`, '404 Not Found');
        return;
      }
      answered += 1;
      record({ event: 'answered', method, path, host });
      socket.end('HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n');
      return;
    }
  });
}

const server = createServer(serve);
server.maxConnections = CONCURRENT_LIMIT;
server.on('error', error => {
  if (finished) return;
  finished = true;
  fail(`listening failed: ${error.code}`);
});
const timer = setTimeout(() => {
  finished = true;
  record({ event: 'deadline' });
  process.exit(3);
}, deadline * 1000);

function close() {
  if (finished) return;
  finished = true;
  clearTimeout(timer);
  server.close();
  for (const socket of sockets) socket.destroy();
  record({ event: 'closed', answered, refused });
  process.exit(0);
}

server.listen({ host: address, port: 0, exclusive: true }, () => {
  record({ event: 'listening', address, port: server.address().port });
  process.stdin.on('end', close);
  process.stdin.on('close', close);
  process.stdin.resume();
});
