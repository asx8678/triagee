// Same-origin Phoenix distributions are loaded before this file by root.html.heex.
// Hooks never own assessment form DOM and never store evidence or drafts.
const draftMessage = "Leave this case and discard unsaved assessment changes?";

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

const csrfToken = document.querySelector("meta[name='csrf-token']")?.getAttribute("content");
if (typeof Phoenix === "undefined" || typeof LiveView === "undefined") {
  console.error("[triage] Phoenix client scripts are missing; run `mix assets.setup` and reload.");
} else {
  const liveSocket = new LiveView.LiveSocket("/live", Phoenix.Socket, {
    params: { _csrf_token: csrfToken },
    hooks: { CopyValue, DirtyDraft, FocusReturn },
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
