const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../priv/static/assets/js/app.js'), 'utf8').split('const draftMessage =')[0];
function mount(initial = '[]', blocked = false) {
  let stored = initial;
  const select = {value: '', options: [], replaceChildren(...v) {this.options = v;}, add(v) {this.options.push(v);}};
  const input = {value: 'Urgent'};
  const status = {textContent: ''};
  const events = [];
  const hook = vm.runInNewContext(source + '\nSavedQueueFilters', {
    URLSearchParams, location: {search: '?team=alpha&kev=yes&after_cve=secret&admin=true'},
    Option: function(text, value) {this.text = text; this.value = value;},
    localStorage: {getItem() {return stored;}, setItem(_, value) {if (blocked) throw Error(); stored = value;}}
  });
  const instance = {el: {querySelector(q) {return q === 'select' ? select : q === 'input' ? input : status;}, addEventListener() {}, removeEventListener() {}}, pushEvent(...v) {events.push(v);}};
  hook.mounted.call(instance);
  return {select, input, status, events, stored: () => JSON.parse(stored), click: action => instance.click({target: {dataset: {savedAction: action}}})};
}
test('save, replace, reload, load and delete filters without cursor or arbitrary keys', () => {
  const a = mount(); a.click('save');
  assert.deepEqual(a.stored(), [{name: 'Urgent', filters: {team: 'alpha', kev: 'yes'}}]);
  a.click('save'); assert.equal(a.stored().length, 1);
  const b = mount(JSON.stringify(a.stored())); b.select.value = '0'; b.click('load');
  assert.equal(JSON.stringify(b.events), JSON.stringify([['filter_queue', {team: 'alpha', kev: 'yes'}]]));
  b.click('delete'); assert.deepEqual(b.stored(), []);
});
test('malformed storage recovers and denied writes report failure', () => {
  const a = mount('{invalid'); assert.match(a.status.textContent, /invalid/); a.click('save'); assert.equal(a.stored().length, 1);
  const b = mount('[]', true); b.click('save'); assert.match(b.status.textContent, /not saved/); assert.deepEqual(b.stored(), []);
});
test('names stay text and entries are capped', () => {
  const a = mount(); a.input.value = '<img src=x onerror=alert(1)>'; a.click('save');
  assert.equal(a.select.options[1].text, a.input.value);
  const b = mount(JSON.stringify(Array.from({length: 20}, (_, i) => ({name: String(i), filters: {}})))); b.click('save'); assert.match(b.status.textContent, /limit 20/);
});
