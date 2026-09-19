const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = 'const WorkspaceDialog =' + fs.readFileSync(path.join(__dirname, '../priv/static/assets/js/app.js'), 'utf8').split('const WorkspaceDialog =')[1].split('const csrfToken =')[0];
function hooks(extra = {}) {
  return vm.runInNewContext(source + '\n({WorkspaceDialog, WorkspaceDraftGuard})', extra);
}
test('native dialog opens, cancels through the server, restores focus, and removes listeners', () => {
  let focused = false;
  const opener = {isConnected: true, focus() {focused = true;}};
  const events = [];
  const listeners = new Map();
  const el = {open:false, dataset:{closeEvent:'close-inspector'}, addEventListener(k,v){listeners.set(k,v);}, removeEventListener(k){listeners.delete(k);}, showModal(){this.open=true;}, close(){this.open=false;}};
  const h = hooks({document:{activeElement:opener}}).WorkspaceDialog;
  const instance = {el,pushEvent(...args){events.push(args);}};
  h.mounted.call(instance);
  assert.equal(el.open,true);
  let prevented=false;
  listeners.get('cancel')({preventDefault(){prevented=true;}});
  assert.equal(prevented,true);
  assert.equal(events[0][0],'close-inspector');
  h.destroyed.call(instance);
  assert.equal(el.open,false);
  assert.equal(focused,true);
  assert.equal(listeners.size,0);
});
test('backdrop closes while inside clicks and drags do not', () => {
  const events = [];
  const listeners = new Map();
  const el = {open: true, dataset: {closeEvent: 'close-inspector'},
    getBoundingClientRect() { return {left: 100, right: 400, top: 0, bottom: 600}; },
    addEventListener(k, v) { listeners.set(k, v); },
    removeEventListener(k) { listeners.delete(k); }, close() {}};
  const h = hooks({document: {activeElement: null, getElementById: () => null}}).WorkspaceDialog;
  const instance = {el, pushEvent(name) { events.push(name); }};
  h.mounted.call(instance);
  const click = (start, end) => {
    listeners.get('mousedown')({clientX: start, clientY: 300});
    listeners.get('click')({clientX: end, clientY: 300});
  };
  click(200, 200);
  click(200, 40);
  click(40, 200);
  assert.equal(events.length, 0);
  click(40, 40);
  assert.deepEqual(events, ['close-inspector']);
  h.destroyed.call(instance);
  assert.equal(listeners.size, 0);
});
function guard(dirty = 'false', confirmed = false) {
  const wrapper = new EventTarget();
  const window = new EventTarget();
  const handlers = new Map();
  const h = hooks({window,URL,location:{href:'http://localhost/workspace',origin:'http://localhost'},confirm:()=>confirmed}).WorkspaceDraftGuard;
  const instance = {el:{dataset:{dirty},closest(){return wrapper;}},handleEvent(k,v){handlers.set(k,v);}};
  h.mounted.call(instance);
  const edit = () => instance.edited({target:{closest(){return {};}}});
  const submit = () => instance.submitting({target:{id:'workspace-decision'}});
  const acknowledge = () => handlers.get('workspace-draft-cleared')({});
  const unload = () => {
    const event = new Event('beforeunload', {cancelable:true});
    window.dispatchEvent(event);
    return event.defaultPrevented;
  };
  const click = (href, patch = false, overrides = {}) => {
    let prevented = false;
    const link = {href,hasAttribute(){return false;},getAttribute(){return patch ? 'patch' : null;}};
    instance.leave({button:0,target:{closest(){return link;}},preventDefault(){prevented=true;},stopImmediatePropagation(){},...overrides});
    return prevented;
  };
  return {h,instance,edit,submit,acknowledge,unload,click};
}

test('dirty guard preserves only LiveView patches, blocks destructive leave, and cleans up', () => {
  const g = guard('true');
  assert.equal(g.unload(),true);
  assert.equal(g.click('http://localhost/workspace#tl-chart'),false);
  assert.equal(g.click('http://localhost/timeline#tl-chart'),true);
  assert.equal(g.click('http://localhost/timeline?weeks=4', true),false);
  assert.equal(g.click('http://localhost/timeline?weeks=4'),true);
  assert.equal(g.click('http://localhost/?page=review', true),false);
  assert.equal(g.click('http://localhost/?page=review'),true);
  assert.equal(g.click('http://localhost/workspace?page=review', true),false);
  assert.equal(g.click('http://localhost/workspace?page=review'),true);
  assert.equal(g.click('http://localhost/import'),true);
  assert.equal(g.click('http://localhost/import', false, {ctrlKey:true}),false);
  g.instance.el.dataset.dirty='false';
  assert.equal(g.unload(),false);
  g.instance.el.dataset.dirty='true';
  g.h.destroyed.call(g.instance);
  assert.equal(g.unload(),false);
});

test('unacknowledged edits remain guarded through unrelated patches and late save acknowledgements', () => {
  const g = guard();
  g.edit();
  assert.equal(g.unload(),true);
  g.instance.el.dataset.dirty='false'; // An older unrelated server patch.
  assert.equal(g.unload(),true);
  g.submit();
  g.edit(); // Typed while a save was in flight.
  g.acknowledge();
  assert.equal(g.unload(),true);
  g.submit();
  g.acknowledge();
  assert.equal(g.unload(),false);
  g.h.destroyed.call(g.instance);
});

test('discard confirmation can clear local edits but never another server-side dirty draft', () => {
  const g = guard();
  g.edit();
  g.instance.confirming({target:{closest(){return {};}}});
  g.acknowledge();
  assert.equal(g.unload(),false);
  g.instance.el.dataset.dirty='true';
  assert.equal(g.unload(),true);
  g.h.destroyed.call(g.instance);
});

test('explicitly confirmed leave avoids a duplicate beforeunload warning', () => {
  const g = guard('true', true);
  assert.equal(g.click('http://localhost/import'),false);
  assert.equal(g.unload(),false);
  g.h.destroyed.call(g.instance);
});
