import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('./bridge.js', import.meta.url), 'utf8');
const listeners = new Map();
const messages = [];
class Element {
  closest(selector) {
    return selector === '[data-page]' ? { dataset: { page: 'profiles' } } : null;
  }
}
const window = {
  addEventListener(name, listener, options) {
    assert.equal(options.capture, true);
    assert.equal(options.passive, true);
    listeners.set(name, listener);
  },
  webkit: { messageHandlers: { cfmIntegration: { postMessage(body) {
    messages.push(body);
    return Promise.resolve(null);
  } } } },
};
vm.runInNewContext(source, { window, Element, console });
const forbidden = () => assert.fail('Observation must not affect event propagation');
listeners.get('click')({ target: new Element(), preventDefault: forbidden, stopPropagation: forbidden });
assert.equal(messages.at(-1).args.dataPage, 'profiles');
assert.equal(messages.at(-1).args.dataAction, null);
listeners.get('keydown')({ key: 'Escape', preventDefault: forbidden, stopPropagation: forbidden });
assert.equal(messages.at(-1).args.key, 'Escape');
listeners.get('error')({ message: 'x'.repeat(800), preventDefault: forbidden, stopPropagation: forbidden });
assert.equal(messages.at(-1).args.message.length, 512);
listeners.get('unhandledrejection')({ reason: new Error('fixture rejection'), preventDefault: forbidden });
assert.equal(messages.at(-1).args.message, 'fixture rejection');
for (let i = 0; i < 1100; i++) listeners.get('keydown')({ key: 'Tab' });
assert.equal(messages.length, 1000, 'Observation count is bounded without changing page events');
let callbackValue;
const id = window.__TAURI_INTERNALS__.transformCallback(value => { callbackValue = value; });
window.__CFM_COMPONENT_TEST__.deliver(id, { index: 0, message: 'fixture' });
assert.equal(callbackValue.message, 'fixture');
window.__TAURI_INTERNALS__.unregisterCallback(id);
assert.equal(window.__CFM_COMPONENT_TEST__.callbackCount(), 0);
console.log('PASS: passive capture, bounded messages/count, and original callback transport');
