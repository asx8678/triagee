// Same-origin Phoenix distributions are loaded before this file by root.html.heex.
// Hooks never own assessment form DOM and never store evidence or drafts.
// Saved views are browser-local preferences, never an authorization boundary.
const SavedQueueFilters = {
  mounted() {
    const key = "triage.saved-queue-filters.v1";
    const allowed = ["q", "team", "severity", "kev", "exposure"];
    const select = this.el.querySelector("select");
    const feedback = this.el.querySelector('[role="status"]');
    const clean = (filters) => Object.fromEntries(allowed.flatMap(name =>
      typeof filters?.[name] === "string" && filters[name].length <= 200
        ? [[name, filters[name]]] : []));
    let views = [];
    try {
      const stored = JSON.parse(localStorage.getItem(key) || "[]");
      if (Array.isArray(stored)) views = stored.filter(v => typeof v?.name === "string" && v.name.length <= 80)
        .slice(0, 20).map(v => ({name: v.name, filters: clean(v.filters)}));
    } catch (_) { feedback.textContent = "Saved views unavailable or invalid; filters still work."; }
    const render = () => {
      select.replaceChildren(new Option("Choose saved filters", ""));
      views.forEach((view, index) => select.add(new Option(view.name, String(index))));
    };
    const persist = (next) => {
      try {
        localStorage.setItem(key, JSON.stringify(next));
        views = next;
        render();
        feedback.textContent = "Saved views updated on this browser.";
      } catch (_) { feedback.textContent = "Browser storage unavailable; changes were not saved."; }
    };
    this.click = (event) => {
      const action = event.target.dataset.savedAction;
      if (action === "save") {
        const name = this.el.querySelector("input").value.trim();
        if (!name || name.length > 80) { feedback.textContent = "Enter a name (1–80 characters)."; return; }
        const next = views.filter(v => v.name !== name);
        if (next.length >= 20) { feedback.textContent = "Delete a saved view first (limit 20)."; return; }
        const filters = clean(Object.fromEntries(new URLSearchParams(location.search)));
        persist([...next, {name, filters}]);
      } else if (select.value !== "" && views[Number(select.value)]) {
        const index = Number(select.value);
        if (action === "load") this.pushEvent("filter_queue", views[index].filters);
        if (action === "delete") persist(views.filter((_, i) => i !== index));
      }
    };
    this.el.addEventListener("click", this.click);
    render();
  },
  destroyed() { this.el.removeEventListener("click", this.click); }
};

const draftMessage = "Leave this case and discard unsaved assessment changes?";

const TimelineWidth = {
  mounted() {
    this.measure = () => {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => {
        const style = getComputedStyle(this.el);
        const width = Math.max(240, Math.min(7680, Math.floor(this.el.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight))));
        if (width !== this.width) {
          this.width = width;
          this.pushEvent("plot_width", {width});
        }
      }, 100);
    };
    this.observer = new ResizeObserver(this.measure);
    this.observer.observe(this.el);
    this.measure();
    this.reveal = () => {
      const selected = this.el.querySelector(".tl-chart-track.tl-selected");
      const target = selected || this.el;
      this.el.focus({preventScroll: true});
      target.scrollIntoView({behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center", inline: "nearest"});
    };
    this.onDetail = (event) => {
      const link = event.target.closest?.("a[id^='tl-open-'], a[id^='tl-lane-open-']");
      if (!link || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const cve = new URL(link.href, location.href).searchParams.get("cve");
      if (cve && cve === this.el.dataset.selectedCve) this.reveal();
    };
    document.addEventListener("click", this.onDetail);
    this.selected = this.el.dataset.selectedCve;
    if (this.selected) this.reveal();
  },
  updated() {
    const selected = this.el.dataset.selectedCve;
    if (selected && selected !== this.selected) this.reveal();
    this.selected = selected;
  },
  destroyed() {
    clearTimeout(this.timer);
    this.observer.disconnect();
    document.removeEventListener("click", this.onDetail);
  }
};

const CopyValue = {
  mounted() {
    this.copy = async () => {
      const feedback = document.getElementById(this.el.dataset.copyFeedback);
      if (feedback) feedback.textContent = "Copying…";
      try {
        if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
        await navigator.clipboard.writeText(this.el.dataset.copyValue);
        if (feedback) feedback.textContent = "Exact value copied.";
      } catch (_error) {
        if (feedback) feedback.textContent = "Copy unavailable. Select and copy the full value above.";
      }
    };
    this.el.addEventListener("click", this.copy);
  },
  destroyed() { this.el.removeEventListener("click", this.copy); },
};

const DirtyDraft = {
  mounted() {
    this.dirty = this.el.dataset.dirty === "true";
    this.editVersion = 0;
    this.submittedVersion = 0;
    this.markDirty = () => { this.dirty = true; this.editVersion += 1; };
    this.beforeUnload = (event) => {
      if (!this.dirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    this.guardLink = (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const link = event.target.closest?.("a[href]");
      if (!this.dirty || !link || link.dataset.draftPreserving === "true" || link.hasAttribute("download") || (link.target && link.target !== "_self")) return;
      const destination = new URL(link.href, location.href);
      if (destination.origin === location.origin && destination.pathname === location.pathname && destination.search === location.search && destination.hash) return;
      if (!window.confirm(draftMessage)) {
        event.preventDefault();
        event.stopImmediatePropagation();
        link.focus();
      } else {
        // Avoid a second beforeunload prompt after this explicit confirmation.
        this.dirty = false;
      }
    };
    this.submitting = () => { this.submittedVersion = this.editVersion; };
    this.discarding = (event) => {
      if (event.target.closest?.('[phx-click="discard_confirmed"]')) this.submittedVersion = this.editVersion;
    };
    // The Navigation API can cancel same-document browser Back/Forward before
    // LiveView changes route. No sentinel entries, history rewrites, or traps.
    this.guardHistory = (event) => {
      if (!this.dirty || event.navigationType !== "traverse" || !event.cancelable) return;
      if (!window.confirm(draftMessage)) event.preventDefault();
      else this.dirty = false;
    };
    this.el.addEventListener("input", this.markDirty);
    this.el.addEventListener("change", this.markDirty);
    this.el.addEventListener("submit", this.submitting, true);
    window.addEventListener("beforeunload", this.beforeUnload);
    document.addEventListener("click", this.guardLink, true);
    document.addEventListener("click", this.discarding, true);
    window.navigation?.addEventListener("navigate", this.guardHistory);
    this.handleEvent("draft-saved", () => {
      // A response to an older submission must not clear newer client edits.
      if (this.editVersion === this.submittedVersion) this.dirty = false;
    });
  },
  updated() {
    // Only the explicit server success/discard event may clear a local draft;
    // an unrelated patch with a stale data-dirty=false cannot clear it.
    if (this.el.dataset.dirty === "true") this.dirty = true;
  },
  destroyed() {
    this.el.removeEventListener("input", this.markDirty);
    this.el.removeEventListener("change", this.markDirty);
    this.el.removeEventListener("submit", this.submitting, true);
    window.removeEventListener("beforeunload", this.beforeUnload);
    document.removeEventListener("click", this.guardLink, true);
    document.removeEventListener("click", this.discarding, true);
    window.navigation?.removeEventListener("navigate", this.guardHistory);
  },
};

// Optional nonmodal confirmation-region hook: focus the first action when the
// region opens and restore its trigger on removal. No dialog/focus trap claim.
const FocusReturn = {
  mounted() {
    this.trigger = document.activeElement;
    this.el.querySelector('button:not([disabled]), a[href], input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex="0"]')?.focus();
  },
  destroyed() {
    const trigger = document.getElementById(this.el.dataset.returnFocus) || this.trigger;
    if (trigger?.isConnected) trigger.focus();
  },
};

const navigationMedia = window.matchMedia("(max-width: 760px)");
const initializedMenus = new WeakSet();
function syncNavigation(reset = false) {
  const menu = document.getElementById("navigation-menu");
  if (!menu) return;
  if (reset || !initializedMenus.has(menu)) {
    menu.open = !navigationMedia.matches;
    initializedMenus.add(menu);
  }
}
function closeNavigation(event) {
  if (event.key !== "Escape" || !navigationMedia.matches) return;
  const menu = document.getElementById("navigation-menu");
  if (menu?.open && menu.contains(document.activeElement)) {
    menu.open = false;
    document.getElementById("navigation-toggle")?.focus();
  }
}
navigationMedia.addEventListener("change", () => syncNavigation(true));
window.addEventListener("phx:page-loading-stop", () => syncNavigation(true));
document.addEventListener("triage:navigation-ready", () => syncNavigation(true));
document.addEventListener("keydown", closeNavigation);
syncNavigation();

// Native modal owns focus trapping/inertness; LiveView still owns all child DOM.
const WorkspaceDialog = {
  mounted() {
    this.opener = document.activeElement;
    this.cancel = event => { event.preventDefault(); this.pushEvent(this.el.dataset.closeEvent, {}); };
    // Clicking the modal backdrop — anywhere outside the dialog box — dismisses
    // it exactly like Escape. A press that starts inside the panel is left
    // alone, so selecting evidence text and releasing outside does not close it.
    this.inside = event => {
      const rect = this.el.getBoundingClientRect();
      return event.clientX >= rect.left && event.clientX <= rect.right &&
        event.clientY >= rect.top && event.clientY <= rect.bottom;
    };
    this.press = event => { this.pressOutside = !this.inside(event); };
    this.backdrop = event => {
      if (this.pressOutside && !this.inside(event)) this.pushEvent(this.el.dataset.closeEvent, {});
    };
    this.el.addEventListener("cancel", this.cancel);
    this.el.addEventListener("mousedown", this.press);
    this.el.addEventListener("click", this.backdrop);
    if (!this.el.open) this.el.showModal();
  },
  updated() { if (!this.el.open) this.el.showModal(); },
  destroyed() {
    this.el.removeEventListener("cancel", this.cancel);
    this.el.removeEventListener("mousedown", this.press);
    this.el.removeEventListener("click", this.backdrop);
    this.el.close();
    if (this.opener?.isConnected) this.opener.focus({preventScroll: true});
    else document.getElementById("main-content")?.focus({preventScroll: true});
  }
};

// Sensitive drafts never enter browser storage. Patches preserve server memory;
// leaving/reloading warns rather than claiming durable draft persistence.
const WorkspaceDraftGuard = {
  mounted() {
    this.wrapper = this.el.closest(".approved-workspace");
    this.localDirty = false;
    this.editVersion = 0;
    this.submittedVersion = -1;
    this.leaving = false;
    this.dirty = () => !this.leaving && (this.localDirty || this.el.dataset.dirty === "true");
    // Protect keystrokes/checkbox changes before a slow or disconnected server
    // can acknowledge them. Unrelated patches must never clear this state.
    this.edited = event => {
      if (!event.target.closest?.("#workspace-decision")) return;
      this.localDirty = true;
      this.editVersion++;
    };
    this.submitting = event => {
      if (event.target.id === "workspace-decision") this.submittedVersion = this.editVersion;
    };
    this.confirming = event => {
      if (event.target.closest?.('[phx-click="new-draft"], [phx-click="confirm-risk"]')) {
        this.submittedVersion = this.editVersion;
      }
    };
    this.handleEvent("workspace-draft-cleared", () => {
      if (this.editVersion === this.submittedVersion) this.localDirty = false;
    });
    this.unload = event => { if (this.dirty()) { event.preventDefault(); event.returnValue = ""; } };
    this.leave = event => {
      const link = event.target.closest?.("a[href]");
      if (!link || !this.dirty() || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      if (link.hasAttribute("download") || (link.target && link.target !== "_self")) return;
      const url = new URL(link.href, location.href);
      const current = new URL(location.href);
      if (url.origin === current.origin && url.pathname === current.pathname && url.search === current.search && url.hash) return;
      if (url.origin === location.origin && ["/", "/workspace", "/timeline"].includes(url.pathname) && link.getAttribute("data-phx-link") === "patch") return;
      if (!confirm("Leave this workspace? Drafts are held only in this live connection and may be lost.")) {
        event.preventDefault(); event.stopImmediatePropagation();
      } else {
        this.leaving = true; // No second beforeunload prompt after explicit consent.
      }
    };
    window.addEventListener("beforeunload", this.unload);
    this.wrapper.addEventListener("input", this.edited);
    this.wrapper.addEventListener("change", this.edited);
    this.wrapper.addEventListener("submit", this.submitting, true);
    this.wrapper.addEventListener("click", this.confirming, true);
    this.wrapper.addEventListener("click", this.leave, true);
  },
  destroyed() {
    window.removeEventListener("beforeunload", this.unload);
    this.wrapper.removeEventListener("input", this.edited);
    this.wrapper.removeEventListener("change", this.edited);
    this.wrapper.removeEventListener("submit", this.submitting, true);
    this.wrapper.removeEventListener("click", this.confirming, true);
    this.wrapper.removeEventListener("click", this.leave, true);
  }
};

const csrfToken = document.querySelector("meta[name='csrf-token']")?.getAttribute("content");
if (typeof Phoenix === "undefined" || typeof LiveView === "undefined") {
  console.error("[triage] Phoenix client scripts are missing; run `mix assets.setup` and reload.");
} else {
  const liveSocket = new LiveView.LiveSocket("/live", Phoenix.Socket, {
    params: { _csrf_token: csrfToken },
    hooks: { CopyValue, DirtyDraft, FocusReturn, TimelineWidth, SavedQueueFilters, WorkspaceDialog, WorkspaceDraftGuard },
  });
  window.liveSocket = liveSocket;
  liveSocket.connect();
}

// Delegation also covers notices inserted by a LiveView patch. Only the actual
// close button dismisses a notice; selecting text or following links never does.
document.addEventListener("click", (event) => {
  const close = event.target.closest?.("[data-flash-close]");
  if (close) {
    const notice = close.closest("[data-flash]");
    const main = document.getElementById("main-content");
    if (notice) notice.hidden = true;
    main?.focus({ preventScroll: true });
  }
});
