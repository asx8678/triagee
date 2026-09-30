// Same-origin Phoenix distributions are loaded before this file by root.html.heex.
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

// Drafts are stored on the server as they change. Leaving warns only while a
// change is still on its way, was made while disconnected, or could not be
// stored (data-dirty); a stored draft never triggers the prompt.
const WorkspaceDraftGuard = {
  mounted() {
    this.wrapper = this.el.closest(".approved-workspace");
    this.leaving = false;
    this.offlineEdit = false;
    // LiveView marks an event it has sent but not yet had answered.
    this.inFlight = () => !!this.wrapper.querySelector(
      "#workspace-decision.phx-change-loading, #workspace-decision.phx-submit-loading, #workspace-decision .phx-change-loading, #workspace-decision .phx-click-loading"
    );
    this.dirty = () => !this.leaving && (this.el.dataset.dirty === "true" || this.offlineEdit || this.inFlight());
    this.edited = event => {
      if (event.target.closest?.("#workspace-decision") && !this.liveSocket.isConnected()) this.offlineEdit = true;
    };
    this.handleEvent("workspace-draft-cleared", () => { this.offlineEdit = false; });
    this.unload = event => { if (this.dirty()) { event.preventDefault(); event.returnValue = ""; } };
    this.leave = event => {
      const link = event.target.closest?.("a[href]");
      if (!link || !this.dirty() || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      if (link.hasAttribute("download") || (link.target && link.target !== "_self")) return;
      const url = new URL(link.href, location.href);
      const current = new URL(location.href);
      if (url.origin === current.origin && url.pathname === current.pathname && url.search === current.search && url.hash) return;
      if (url.origin === location.origin && ["/", "/workspace", "/timeline"].includes(url.pathname) && link.getAttribute("data-phx-link") === "patch") return;
      if (!confirm("Leave this page? Your latest change hasn't been saved yet.")) {
        event.preventDefault(); event.stopImmediatePropagation();
      } else {
        this.leaving = true; // No second beforeunload prompt after explicit consent.
      }
    };
    window.addEventListener("beforeunload", this.unload);
    this.wrapper.addEventListener("input", this.edited);
    this.wrapper.addEventListener("change", this.edited);
    this.wrapper.addEventListener("click", this.leave, true);
  },
  // On reconnect LiveView sends the form again; if storing it fails the
  // server marks the draft unsaved through data-dirty.
  reconnected() { this.offlineEdit = false; },
  destroyed() {
    window.removeEventListener("beforeunload", this.unload);
    this.wrapper.removeEventListener("input", this.edited);
    this.wrapper.removeEventListener("change", this.edited);
    this.wrapper.removeEventListener("click", this.leave, true);
  }
};

// The CVE list is one Tab stop; the arrow keys, Home and End move between rows.
const QueueKeys = {
  mounted() {
    this.onKey = event => {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      const rows = [...this.el.querySelectorAll(".queue-item")];
      const index = rows.indexOf(document.activeElement);
      const next = { ArrowDown: index + 1, ArrowUp: index - 1, Home: 0, End: rows.length - 1 }[event.key];
      if (index < 0 || next === undefined || !rows[next]) return;
      event.preventDefault();
      rows.forEach(row => { row.tabIndex = row === rows[next] ? 0 : -1; });
      rows[next].focus();
    };
    this.el.addEventListener("keydown", this.onKey);
  },
  destroyed() { this.el.removeEventListener("keydown", this.onKey); }
};

const csrfToken = document.querySelector("meta[name='csrf-token']")?.getAttribute("content");
if (typeof Phoenix === "undefined" || typeof LiveView === "undefined") {
  console.error("[triage] Phoenix client scripts are missing; run `mix assets.setup` and reload.");
} else {
  const liveSocket = new LiveView.LiveSocket("/live", Phoenix.Socket, {
    params: { _csrf_token: csrfToken },
    hooks: { QueueKeys, TimelineWidth, WorkspaceDialog, WorkspaceDraftGuard },
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
