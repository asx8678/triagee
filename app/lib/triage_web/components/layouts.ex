defmodule TriageWeb.Layouts do
  @moduledoc "Application shell and persistent, runtime-grounded safety context."
  use TriageWeb, :html

  embed_templates "layouts/*"

  attr :flash, :map, required: true
  attr :active_page, :string, default: nil
  attr :current_scope, :map, default: nil
  slot :inner_block, required: true

  def app(assigns) do
    assigns = assign(assigns, :runtime, runtime_notice())

    ~H"""
    <a href="#main-content" class="triage-skip-link">Skip to content</a>
    <div class="app-shell">
      <header class="triage-topbar">
        <div class="topbar-inner">
          <a href="/" class="triage-brand" aria-label="PTV Triage overview">
            <img
              src={~p"/images/triage-wordmark-v2.png"}
              width="1280"
              height="187"
              class="triage-brand-logo"
              alt="PTV Triage"
            />
          </a>
          <details
            id="navigation-menu"
            class="navigation-disclosure"
            open
            phx-mounted={JS.dispatch("triage:navigation-ready")}
          >
            <summary id="navigation-toggle" aria-controls="primary-navigation">Navigation</summary>
            <nav id="primary-navigation" class="triage-nav" aria-label="Primary">
              <details
                :for={{group, links} <- navigation_groups()}
                open={group == "Workspace" or group_active?(links, @active_page)}
                class={["nav-group", nav_group_class(group)]}
              >
                <summary class="nav-group-label">{group}</summary>
                <.link
                  :for={{key, label, path} <- links}
                  id={"nav-#{key}"}
                  href={path}
                  class="triage-nav-link"
                  aria-current={if @active_page == key, do: "page", else: nil}
                >
                  {label}
                </.link>
              </details>
            </nav>
          </details>
        </div>
      </header>
      <div class="app-body">
        <section
          id="environment-notice"
          class="environment-notice"
          aria-label="Environment and safety"
        >
          <div class="cluster environment-summary">
            <strong>Local workspace · No sign-in · {@runtime.binding}</strong>
            <span>Collection disabled · Production coverage unknown</span>
          </div>
          <details id="safety-details">
            <summary>Safety details</summary>
            <div class="stack">
              <p>Live collection is disabled. Production coverage is unknown.</p>
              <p>
                The local-operator identity is unauthenticated: there is no authentication or
                authorization. Keep this app on loopback. {@runtime.binding_detail}
              </p>
              <p>
                Team and environment filters only change what is displayed; filters are not
                access control. Saved case scope remains immutable.
              </p>
              <p>
                Local records may come from synthetic fixtures, imports, or replays; their
                provenance is shown in the relevant workflow. The application cannot establish
                production coverage. {@runtime.collection_detail}
              </p>
              <p>
                Browsing does not create cases, refresh evidence, or run tools. Explicit actions
                can write local records. An assessment does not approve an exception, suppress a
                finding, or verify a fix.
              </p>
            </div>
          </details>
        </section>
        <main id="main-content" class="triage-main" tabindex="-1">
          <div class="triage-content">
            <.flash_group flash={@flash} />
            {render_slot(@inner_block)}
          </div>
        </main>
      </div>
    </div>
    """
  end

  # A group stays open when it holds the page on screen, so the current
  # destination is never hidden behind a collapsed disclosure and its
  # aria-current marking stays visible.
  defp group_active?(links, active_page) do
    Enum.any?(links, fn {key, _label, _path} -> key == active_page end)
  end

  defp nav_group_class("Data tools"), do: "nav-group-tools"
  defp nav_group_class(_other), do: "nav-group-primary"

  defp navigation_groups do
    [
      {"Workspace",
       [
         {"findings", "Vulnerabilities", ~p"/"},
         {"triage", "Review", ~p"/triage"},
         {"timeline", "Timeline", ~p"/timeline"}
       ]},
      {"Data tools",
       [
         {"statistics", "Statistics", ~p"/statistics"},
         {"imports", "Imports", ~p"/imports"},
         {"replay", "Replay", ~p"/replay"},
         {"intel", "Intel", ~p"/intel"}
       ]}
    ]
  end

  @doc "Presentation of the actual listener configuration and compile-time collection policy."
  def runtime_notice do
    http = TriageWeb.Endpoint.config(:http) || []
    https = TriageWeb.Endpoint.config(:https) || []
    listeners = Enum.reject([http, https], &(&1 == []))
    loopback? = listeners != [] and Enum.all?(listeners, &loopback_ip?(&1[:ip]))

    %{
      binding: if(loopback?, do: "Loopback only", else: "Listener binding unverified"),
      binding_detail:
        if(loopback?,
          do: "Configured listeners use loopback addresses.",
          else: "A loopback-only listener could not be verified from runtime configuration."
        ),
      collection_detail: collection_detail(Triage.Collection.Transport.loopback_enabled?())
    }
  end

  defp collection_detail(enabled?) do
    Map.fetch!(
      %{
        true =>
          "This test build permits only explicitly configured loopback test collection; live production collection is unavailable.",
        false =>
          "This build disables network collection; imports and local replay do not contact live production sources."
      },
      enabled?
    )
  end

  defp loopback_ip?({127, _, _, _}), do: true
  defp loopback_ip?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp loopback_ip?(_), do: false

  attr :flash, :map, required: true
  attr :id, :string, default: "flash-group"

  def flash_group(assigns) do
    ~H"""
    <div id={@id}>
      <div
        id="connection-notice"
        class="notice notice-error"
        role="status"
        hidden
        phx-disconnected={JS.remove_attribute("hidden", to: "#connection-notice")}
        phx-connected={JS.set_attribute({"hidden", ""}, to: "#connection-notice")}
      >
        <strong>Connection interrupted</strong>
        Check that the local service is running. Reconnection is automatic. Keep this tab open to retain unsaved assessment text; a save is not confirmed until a result appears.
      </div>
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />
    </div>
    """
  end
end
