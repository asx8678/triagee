defmodule TriageWeb.CveLive.Show do
  @moduledoc """
  Advisory-level aggregate detail: every current occurrence across teams,
  images and placements, with exposure evidence and a deterministic,
  explainable review priority.

  Public intelligence is shown only as provenance-tagged cached data
  (`fetched_at` visible); absence of a cached advisory never means
  "not known" or "not exploited". Suppressed occurrences stay labelled —
  suppression is not mitigation evidence.
  """

  use TriageWeb, :live_view

  alias Triage.{Intel, Inventory, Risk}
  alias TriageWeb.FindingFilters

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Advisory detail")
     |> assign(:invalid_scope, [])
     |> assign(:scope, %{owner: nil, environment: nil})
     |> assign(:detail, nil)
     |> assign(:risk, nil)
     |> assign(:kev_advisories, [])
     |> assign(:nvd_advisories, [])
     |> assign(:kev_matched?, false)}
  end

  @impl true
  def handle_params(%{"id" => id} = params, _uri, socket) do
    parsed = FindingFilters.parse(params)
    scope = %{owner: parsed.owner, environment: parsed.environment}
    socket = assign(socket, :list_query, FindingFilters.query_params(parsed))

    if parsed.invalid != [] do
      {:noreply,
       socket
       |> assign(:invalid_scope, parsed.invalid)
       |> assign(:scope, scope)
       |> assign(:detail, nil)
       |> assign(:risk, nil)}
    else
      case Inventory.fetch_cve(id, owner: scope.owner, environment: scope.environment) do
        {:ok, detail} ->
          kev = Intel.cached_kev(detail.cve)
          nvd = Intel.cached_nvd(detail.cve)

          {:noreply,
           socket
           |> assign(:page_title, detail.cve)
           |> assign(:invalid_scope, [])
           |> assign(:scope, scope)
           |> assign(:detail, detail)
           |> assign_intel(kev, nvd)
           |> assign(:intel_receipts, Intel.latest_receipts())
           |> assign(:risk, plc_risks(detail, kev != []))}

        {:error, :invalid_cve} ->
          not_found(socket, "Advisory id contains unsafe text")

        {:error, :not_found} ->
          not_found(socket, "Advisory not found in current inventory")
      end
    end
  end

  defp assign_intel(socket, kev, nvd) do
    socket
    |> assign(:kev_advisories, kev)
    |> assign(:nvd_advisories, nvd)
    |> assign(:kev_matched?, kev != [])
  end

  # Placement-level review priorities + CVE-level aggregate (max wins).
  #
  # Severity and fix availability are taken from the occurrences on THIS
  # placement's own image, and exploitation from the cached KEV entry for the
  # advisory. Pairing the advisory's worst severity with an unrelated placement's
  # exposure would fabricate a combination the evidence never showed, and leaving
  # KEV out would make the policy's escalation branch unreachable.
  #
  # The headline aggregate is derived only from placements that are active now.
  # A retired placement keeps its own row priority below, but it must not raise
  # the CVE's current review attention: the CVE list, the review queue and case
  # opening all require an active placement too.
  defp plc_risks(detail, known_exploited?) do
    details =
      Enum.map(detail.placements, fn %{placement: p, exposure: exposure} ->
        occurrences = Enum.filter(detail.occurrences, &(&1.image_id == p.image_id))

        Risk.classify(%{
          "severity" => max_severity(occurrences),
          "exposure" => exposure,
          "known_exploited" => known_exploited?,
          "fix_available" => any_fix_available?(occurrences)
        })
        |> Map.merge(%{
          placement_id: p.id,
          owner: p.owner,
          namespace: p.namespace,
          active: p.active
        })
      end)

    %{aggregate: Risk.aggregate(Enum.filter(details, & &1.active)), details: details}
  end

  defp max_severity(occurrences) do
    occurrences
    |> Enum.map(& &1.severity)
    |> Enum.max_by(&severity_rank/1, fn -> nil end)
  end

  defp severity_rank("CRITICAL"), do: 4
  defp severity_rank("HIGH"), do: 3
  defp severity_rank("MEDIUM"), do: 2
  defp severity_rank("LOW"), do: 1
  defp severity_rank(_other), do: 0

  defp any_fix_available?(occurrences),
    do: Enum.any?(occurrences, fn o -> o.fix not in [nil, ""] end)

  defp not_found(socket, message) do
    {:noreply,
     socket
     |> put_flash(:error, message)
     |> push_navigate(to: ~p"/findings")}
  end

  defp plural(1, singular, _plural), do: singular
  defp plural(_n, _singular, plural), do: plural

  defp team_names(placements) do
    placements
    |> Enum.map(fn %{placement: p} -> p.owner end)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.join(", ")
  end

  defp occurrence_state(o) do
    cond do
      o.suppressed -> "Suppressed (not mitigation evidence)"
      o.resolved_at -> "No longer observed"
      true -> "Open"
    end
  end

  defp image_ref_for(image_id, occurrences) do
    case Enum.find(occurrences, &(&1.image_id == image_id)) do
      nil -> "unknown image"
      o -> image_reference(o.image)
    end
  end

  defp image_reference(%{repository: repo, tag: tag})
       when is_binary(repo) and is_binary(tag),
       do: repo <> ":" <> tag

  defp image_reference(%{repository: repo}) when is_binary(repo), do: repo
  defp image_reference(_other), do: "unknown"

  defp placement_priority(nil, _placement_id), do: "n/a"

  defp placement_priority(%{details: details}, placement_id) do
    case Enum.find(details, &(&1.placement_id == placement_id)) do
      nil -> "n/a"
      risk -> risk.priority
    end
  end

  defp intel_status(receipts, source, rows) do
    receipt = Enum.find(receipts, &(&1.source == source))

    cond do
      receipt && not receipt.succeeded ->
        "Latest refresh failed — #{if rows == [], do: "no retained matching data", else: "older cached data retained"}."

      rows != [] ->
        "Matching cached data available; freshness is not verified by browsing."

      receipt && receipt.succeeded ->
        "Refresh succeeded with no matching entry. This is not evidence that exploitation is absent."

      source == "kev" ->
        "Known exploitation: Unknown — KEV data has not been fetched."

      true ->
        "NVD details: Unavailable — no fetched cache."
    end
  end

  # Which evidence state the local cache is actually in. A source that was never
  # fetched, one whose last refresh failed, one that refreshed with no matching
  # entry and one with a matching entry are four different states: "no cached
  # entry" alone would read as a fact about the world rather than about this
  # workspace, and the reassurance it implies would be unfounded.
  defp kev_match_label(receipts, rows) do
    receipt = Enum.find(receipts, &(&1.source == "kev"))

    cond do
      rows != [] -> "Yes"
      receipt && not receipt.succeeded -> "Unknown — the last KEV refresh failed"
      receipt && receipt.succeeded -> "No match after a successful refresh"
      true -> "Unknown — KEV data has not been fetched"
    end
  end

  defp intel_source("kev", _cve), do: "kev"
  defp intel_source("nvd", cve), do: Intel.nvd_source(cve)

  defp intel_tone(receipts, source, rows) do
    receipt = Enum.find(receipts, &(&1.source == source))

    cond do
      receipt && not receipt.succeeded -> "intel-state-failed"
      rows != [] -> "intel-state-stated"
      true -> "intel-state-unknown"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="findings">
      <%= if @invalid_scope != [] do %>
        <div id="cve-scope-error" class="notice" role="alert">
          <h2>Invalid filters for advisory detail</h2>
          <p>No advisory data was loaded. Fix the filters in the list.</p>
          <.link navigate={~p"/findings"} class="button button-secondary">Back to findings</.link>
        </div>
      <% else %>
        <%= if @detail do %>
          <nav aria-label="Breadcrumb">
            <.link id="cve-back-to-list" navigate={~p"/findings?#{@list_query}"}>
              Vulnerabilities · Back to filtered results
            </.link>
          </nav>
          <.page_header
            id="cve-title"
            title={@detail.cve}
            eyebrow="Advisory"
            subtitle="Aggregate detail across all teams and images in scope — observation data, not proof of exploitability or remediation."
          />

          <div class="cluster">
            <button
              id="cve-copy"
              type="button"
              class="button button-secondary"
              phx-hook="CopyValue"
              data-copy-value={@detail.cve}
              data-copy-feedback="cve-copy-feedback"
              aria-label="Copy advisory identifier"
            >Copy CVE</button>
            <span id="cve-copy-feedback" role="status" aria-live="polite" phx-update="ignore"></span>
            <span>Scanner severity:</span>
            <.status_badge
              label={max_severity(@detail.occurrences) || "Not reported"}
              kind="severity"
            />
          </div>
          <div id="advisory-workspace" class="cve-workspace">
            <aside class="cve-workspace-side" aria-label="Priority, evidence and intelligence">
              <section id="cve-priority" class="stack" aria-labelledby="cve-priority-title">
                <h2 id="cve-priority-title">
                  Review priority (deterministic policy v{Risk.policy_version()})
                </h2>
                <p class="supporting">
                  Scanner severity is never downgraded. Exposure and exploitation evidence only
                  raise review attention. Unknown exposure is never treated as safe.
                </p>
                <%= if @risk.aggregate do %>
                  <div>
                    <.status_badge label={@risk.aggregate.priority} kind="severity" />
                    <span class="supporting">
                      severity {@risk.aggregate.severity} · exposure {@risk.aggregate.exposure}
                    </span>
                  </div>
                  <ul id="cve-priority-reasons">
                    <li :for={reason <- @risk.aggregate.reasons}>{reason}</li>
                  </ul>
                <% else %>
                  <.notice id="cve-priority-empty" kind="info">
                    No placement-level evidence in this scope is currently active, so no current priority
                    can be derived.
                    <%= if Enum.any?(@risk.details, &(!&1.active)) do %>
                      The retired placement below is shown as history only and never raises this headline
                      priority.
                    <% end %>
                  </.notice>
                <% end %>
              </section>

              <section id="cve-descriptions" class="stack" aria-labelledby="cve-descriptions-title">
                <h2 id="cve-descriptions-title">Vulnerability descriptions</h2>
                <p class="supporting">
                  Recorded advisory descriptions for the affected libraries. Package presence alone does not establish exploitability.
                </p>
                <div :for={
                  occurrence <- Enum.uniq_by(@detail.occurrences, &{&1.package_name, &1.description})
                }>
                  <h3>{occurrence.package_name}</h3>
                  <p>
                    {if occurrence.description in [nil, ""],
                      do: "No description recorded",
                      else: occurrence.description}
                  </p>
                </div>
              </section>

              <section id="cve-intel" class="stack" aria-labelledby="cve-intel-title">
                <h2 id="cve-intel-title">Public intelligence (operator-refreshed cache)</h2>
                <p class="supporting">
                  Cached public data only. Opening this page fetches nothing; the cache changes only
                  through an explicit operator run of <code>mix triage.intel --kev</code>
                  or <code>mix triage.intel --nvd</code>.
                  <.link id="cve-intel-receipts-link" navigate={~p"/intel"}>
                    Refresh receipts and cached entries
                  </.link>
                </p>
                <dl id="cve-intel-evidence" class="evidence-grid">
                  <div
                    :for={
                      {kind, label, rows} <- [
                        {"kev", "Known exploitation (KEV)", @kev_advisories},
                        {"nvd", "NVD details", @nvd_advisories}
                      ]
                    }
                    id={"cve-intel-" <> kind}
                    class={[
                      "triage-fact",
                      "intel-state",
                      intel_tone(@intel_receipts, intel_source(kind, @detail.cve), rows)
                    ]}
                  >
                    <dt>{label}</dt>
                    <dd>
                      <p>{intel_status(@intel_receipts, intel_source(kind, @detail.cve), rows)}</p>
                      <p :if={rows != []} class="supporting">
                        Cached entry written <.timestamp value={hd(rows).fetched_at} /> · source
                        <code>{intel_source(kind, @detail.cve)}</code>
                      </p>
                    </dd>
                  </div>
                </dl>
                <p id="cve-intel-summary" class="supporting">
                  KEV cache match: {kev_match_label(@intel_receipts, @kev_advisories)} · NVD entries: {length(
                    @nvd_advisories
                  )}
                </p>
                <ul :if={@kev_advisories != []} id="cve-kev-list">
                  <li :for={a <- @kev_advisories}>
                    <.timestamp value={a.published_at} /> · {a.summary || "no summary cached"}
                  </li>
                </ul>
                <ul :if={@nvd_advisories != []} id="cve-nvd-list">
                  <li :for={a <- @nvd_advisories}>
                    <.timestamp value={a.published_at} /> · {a.summary || "no summary cached"}
                  </li>
                </ul>
              </section>

              <section id="cve-teams" class="stack" aria-labelledby="cve-teams-title">
                <h2 id="cve-teams-title">Teams affected</h2>
                <p>{team_names(@detail.placements)}</p>
              </section>

              <section
                id="cve-next-action"
                class="cve-side-panel"
                aria-labelledby="cve-next-action-title"
              >
                <h2 id="cve-next-action-title">Next supported action</h2>
                <p class="supporting">
                  This page is read-only: it records no assessment. Assessment happens in the review
                  queue for eligible critical, active, unsuppressed occurrences. The queue is not filtered to this advisory; select the advisory and exact scope there.
                </p>
                <.link
                  id="cve-review-queue"
                  navigate={~p"/triage"}
                  class="button"
                >
                  Open review queue
                </.link>
              </section>
            </aside>
            <div class="cve-workspace-main">
              <section id="cve-packages" class="stack" aria-labelledby="cve-packages-title">
                <h2 id="cve-packages-title">Affected libraries</h2>
                <div
                  class="table-region"
                  role="region"
                  tabindex="0"
                  aria-labelledby="cve-packages-title"
                >
                  <table class="data-table">
                    <thead>
                      <tr>
                        <th scope="col">Package</th>
                        <th scope="col">Installed version</th>
                        <th scope="col">Reported fix</th>
                        <th scope="col">Scanner severity</th>
                        <th scope="col">State</th>
                      </tr>
                    </thead>
                    <tbody id="cve-package-rows">
                      <tr :for={o <- @detail.occurrences} id={"cve-occurrence-#{o.id}"}>
                        <td>
                          {o.package_name}
                          <div class="supporting">
                            <.link
                              navigate={~p"/findings/#{o.id}?#{@list_query}"}
                              aria-label={"View occurrence of #{@detail.cve} in #{o.package_name}"}
                            >View occurrence</.link>
                          </div>
                          <.technical_value
                            id={"cve-image-#{o.id}"}
                            label="Image reference"
                            value={image_reference(o.image)}
                            variant="compact"
                          />
                        </td>
                        <td>
                          <.technical_value
                            id={"cve-version-#{o.id}"}
                            label="Package version"
                            value={o.package_version}
                            variant="compact"
                          />
                        </td>
                        <td>
                          {o.fix || "Not reported"}<span
                            :if={o.fix not in [nil, ""]}
                            class="supporting"
                          >Not verified deployed</span>
                        </td>
                        <td>{o.severity || "Not reported"}</td>
                        <td>{occurrence_state(o)}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </section>

              <section id="cve-placements" class="stack" aria-labelledby="cve-placements-title">
                <h2 id="cve-placements-title">Placements, exposure and priority</h2>
                <div
                  class="table-region"
                  role="region"
                  tabindex="0"
                  aria-labelledby="cve-placements-title"
                >
                  <table class="data-table">
                    <thead>
                      <tr>
                        <th scope="col">Image</th>
                        <th scope="col">Team / environment</th>
                        <th scope="col">Namespace</th>
                        <th scope="col">Exposure</th>
                        <th scope="col">Active</th>
                        <th scope="col">Priority</th>
                      </tr>
                    </thead>
                    <tbody id="cve-placement-rows">
                      <tr
                        :for={%{placement: p, exposure: exposure} <- @detail.placements}
                        id={"cve-placement-#{p.id}"}
                      >
                        <td><code>{image_ref_for(p.image_id, @detail.occurrences)}</code></td>
                        <td>{p.owner} / {p.environment}</td>
                        <td>{p.namespace}</td>
                        <td>{exposure}</td>
                        <td>{if p.active, do: "Yes", else: "No"}</td>
                        <td>{placement_priority(@risk, p.id)}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <p class="supporting">
                  Exposure is operator-declared evidence. Missing evidence stays unknown — never safe.
                  Each row's priority uses that image's own occurrences and this placement's exposure,
                  and escalates when the advisory has a cached KEV entry. A retired placement keeps its
                  own row priority; only active placements set the headline above.
                </p>
              </section>

              <section id="cve-lifecycle" class="stack" aria-labelledby="cve-lifecycle-title">
                <h2 id="cve-lifecycle-title">Lifecycle observations</h2>
                <ul id="cve-lifecycle-list">
                  <li :for={o <- @detail.occurrences} id={"cve-lifecycle-#{o.id}"}>
                    {o.package_name} <code>{o.package_version}</code>: first seen
                    <.timestamp value={o.first_seen} /> · last seen <.timestamp value={o.last_seen} />
                    <span :if={o.resolved_at}>· no longer observed
                    <.timestamp value={o.resolved_at} /></span>
                    · reopened {o.reopen_count} {plural(o.reopen_count, "time", "times")}
                  </li>
                </ul>
              </section>
            </div>
          </div>
        <% else %>
          <.notice id="cve-unavailable" kind="warning" title="Advisory unavailable">
            The advisory could not be loaded. <.link navigate={~p"/findings"}>Back to findings</.link>
          </.notice>
        <% end %>
      <% end %>
    </Layouts.app>
    """
  end
end
