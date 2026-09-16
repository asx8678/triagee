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

  alias Triage.{Cases, Exceptions, Intel, Inventory, Risk}
  alias TriageWeb.FindingFilters
  alias TriageWeb.UIComponents

  import TriageWeb.CaseLive.Format, only: [linkable?: 1]
  import TriageWeb.ReferenceComponents, only: [reference_notice: 1]

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
     |> assign(:kev_matched?, false)
     |> assign(:kev_cache, empty_cache())
     |> assign(:nvd_cache, empty_cache())
     |> assign(:triage_targets, %{})
     |> assign(:triage_error, nil)
     |> stream(:triage_targets, [])}
  end

  @impl true
  def handle_params(%{"id" => id} = params, _uri, socket) do
    parsed = FindingFilters.parse(params)
    scope = %{owner: parsed.owner, environment: parsed.environment}

    if parsed.invalid != [] do
      {:noreply,
       socket
       |> assign(:invalid_scope, parsed.invalid)
       |> assign(:scope, scope)
       |> assign(:detail, nil)
       |> assign(:risk, nil)
       |> assign_triage(nil)}
    else
      case Inventory.fetch_cve(id, owner: scope.owner, environment: scope.environment) do
        {:ok, detail} ->
          kev = Intel.cached_kev(detail.cve)
          nvd = Intel.cached_nvd(detail.cve)
          receipts = Intel.latest_receipts()

          {:noreply,
           socket
           |> assign(:page_title, detail.cve)
           |> assign(:invalid_scope, [])
           |> assign(:scope, scope)
           |> assign(:detail, detail)
           |> assign_triage(detail)
           |> assign_intel(kev, nvd)
           |> assign(
             :kev_cache,
             cache_status(receipts, "kev", Intel.cached_advisory_count("kev"))
           )
           |> assign(
             :nvd_cache,
             cache_status(receipts, Intel.nvd_source(detail.cve), length(nvd))
           )
           |> assign(:risk, plc_risks(detail, kev != []))}

        {:error, :invalid_cve} ->
          not_found(socket, "Advisory id contains unsafe text")

        {:error, :not_found} ->
          not_found(socket, "Advisory not found in current inventory")
      end
    end
  end

  # Event parameters select only a displayed target; finding and scope are
  # always server-owned. Cases rechecks active scope before any write.
  @impl true
  def handle_event("open_triage", %{"target" => target}, socket) when is_binary(target) do
    case Map.get(socket.assigns.triage_targets, target) do
      nil ->
        {:noreply,
         assign(socket, :triage_error, "Choose a currently displayed package and scope.")}

      row ->
        case Cases.open_case(row.finding_id, owner: row.owner, environment: row.environment) do
          {:ok, %{case: review_case}} ->
            path =
              ~p"/cases/#{review_case.id}?#{%{owner: row.owner, environment: row.environment}}"

            {:noreply, push_navigate(socket, to: path <> "#review-section")}

          {:error, _reason} ->
            {:noreply,
             assign(
               socket,
               :triage_error,
               "This occurrence is no longer available in that active scope. Reload and choose again."
             )}
        end
    end
  end

  def handle_event("open_triage", _params, socket) do
    {:noreply, assign(socket, :triage_error, "Choose a currently displayed package and scope.")}
  end

  defp assign_triage(socket, detail) do
    targets = triage_targets(detail)
    ids = targets |> Enum.map(& &1.finding_id) |> Enum.uniq()
    statuses = Exceptions.finding_statuses(ids)

    rows =
      Enum.map(targets, fn row ->
        Map.put(
          row,
          :exception_status,
          Map.get(statuses, {row.finding_id, row.owner, row.environment}, :action_required)
        )
      end)

    socket
    |> assign(:triage_targets, Map.new(rows, &{&1.id, &1}))
    |> assign(:triage_error, nil)
    |> stream(:triage_targets, rows, reset: true)
  end

  defp triage_targets(nil), do: []

  defp triage_targets(detail) do
    for finding <- detail.occurrences,
        %{placement: placement} <- detail.placements,
        placement.active and placement.image_id == finding.image_id,
        placement.owner not in [nil, "", "all"],
        placement.environment not in [nil, "", "all"] do
      %{
        id: "#{finding.id}-#{placement.id}",
        finding_id: finding.id,
        package: finding.package_name,
        version: finding.package_version,
        image: image_reference(finding.image),
        owner: placement.owner,
        environment: placement.environment
      }
    end
    |> Enum.uniq_by(&{&1.finding_id, &1.owner, &1.environment})
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
  defp plc_risks(%{placements: []}, _known_exploited?), do: nil

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
        |> Map.merge(%{placement_id: p.id, owner: p.owner, namespace: p.namespace})
      end)

    case Risk.aggregate(details) do
      nil -> nil
      agg -> %{aggregate: agg, details: details}
    end
  end

  defp max_severity(occurrences) do
    occurrences
    |> Enum.map(& &1.severity)
    |> Enum.max_by(&severity_rank/1, fn -> nil end)
  end

  defp severity_rank(value), do: Triage.Severity.rank(value)

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

  # The advisory inventory, filtered by the same search contract the findings
  # page already uses — `q` matches an advisory id or any affected package, so a
  # package link cannot show a different advisory set than the search does — and
  # scoped to the team and environment this advisory page was opened in.
  defp inventory_path(scope, search) do
    qs =
      FindingFilters.query_params(%{
        FindingFilters.defaults()
        | owner: scope.owner,
          environment: scope.environment,
          q: search
      })

    if map_size(qs) == 0, do: ~p"/findings", else: ~p"/findings?#{qs}"
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

  # How much of a source is actually cached, plus the last refresh receipt for it.
  # A receipt is the only evidence that a refresh was attempted, so "no cached
  # entry" can be explained as "never refreshed" or "the last refresh failed"
  # instead of reading as a statement about the advisory.
  defp empty_cache, do: %{rows: 0, attempted_at: nil, succeeded: nil, message: nil}

  defp cache_status(receipts, source, row_count) do
    case Enum.find(receipts, &(&1.source == source)) do
      nil ->
        %{empty_cache() | rows: row_count}

      receipt ->
        %{
          rows: row_count,
          attempted_at: receipt.attempted_at,
          succeeded: receipt.succeeded,
          message: receipt.message
        }
    end
  end

  defp cache_text(%{rows: 0, attempted_at: nil}), do: "never refreshed, 0 rows stored"

  defp cache_text(%{rows: rows, attempted_at: nil}),
    do: "#{rows} #{plural(rows, "row", "rows")} stored, refresh time not recorded"

  defp cache_text(%{rows: rows, attempted_at: at, succeeded: true}),
    do: "#{rows} #{plural(rows, "row", "rows")} stored, refreshed #{relative_at(at)}"

  defp cache_text(%{rows: rows, attempted_at: at, succeeded: false} = cache),
    do:
      "#{rows} #{plural(rows, "row", "rows")} stored, last refresh failed #{relative_at(at)}" <>
        failure_detail(cache.message)

  defp failure_detail(message) when is_binary(message) and message != "", do: " — #{message}"
  defp failure_detail(_other), do: ""

  # Same vocabulary as the overview's receipt labels: an unparseable time is
  # "unknown". A missing attempt never reaches here — the clauses above report it as
  # "never refreshed", because a receipt with no attempt time is not a thing.
  defp relative_at(at), do: UIComponents.relative_time(at) || "unknown"

  defp cached_at(nil), do: "never fetched"
  defp cached_at(%{fetched_at: at}), do: UIComponents.relative_time(at) || "unknown"

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
          <.page_header
            id="cve-title"
            title={@detail.cve}
            eyebrow="Advisory"
            subtitle="Aggregate detail across all teams and images in scope — observation data, not proof of exploitability or remediation."
          >
            <:actions>
              <.link
                id="cve-inventory-link"
                navigate={inventory_path(@scope, @detail.cve)}
                class="button button-secondary"
              >Show in advisory inventory</.link>
              <.copy_value id="cve-copy" label="advisory id" value={@detail.cve} />
            </:actions>
          </.page_header>

          <.reference_notice
            id="cve-reference-source"
            finding={Enum.find(@detail.occurrences, &Triage.ReferenceData.reference_image?(&1.image))}
          />

          <section id="cve-triage" class="assessment-panel stack" aria-labelledby="cve-triage-title">
            <h2 id="cve-triage-title">Triage / action required</h2>
            <p>
              Choose the package, team and environment to assess. Open assessment exposes
              applicability, priority, next action and rationale. Each case covers only this
              occurrence and scope — never every occurrence of the CVE.
            </p>
            <p class="supporting">
              Local exceptions never lower scanner severity or remove inventory/report rows. Status is checked on page load.
              Opening an existing case keeps its evidence and history. Opening a new case
              captures local evidence; simply viewing this page writes nothing.
            </p>
            <p :if={@triage_error} id="cve-triage-error" class="notice" role="alert">
              {@triage_error}
            </p>
            <p :if={map_size(@triage_targets) == 0} id="cve-triage-empty" class="notice">
              No explicit active team/environment placement is available for assessment in this scope.
              Record deployment context before making a scoped decision; missing context does not mean safe.
            </p>
            <div class="table-region" role="region" tabindex="0" aria-label="Scoped triage actions">
              <table class="data-table">
                <thead>
                  <tr>
                    <th scope="col">Package / version</th>
                    <th scope="col">Image</th>
                    <th scope="col">Team / environment</th>
                    <th scope="col">Local action status</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody id="cve-triage-targets" phx-update="stream">
                  <tr :for={{dom_id, target} <- @streams.triage_targets} id={dom_id}>
                    <td>{target.package} <code>{target.version}</code></td>
                    <td><code>{target.image}</code></td>
                    <td>{target.owner} / {target.environment}</td>
                    <td id={"cve-triage-status-#{target.id}"}>
                      {Exceptions.label(target.exception_status)}
                    </td>
                    <td>
                      <button
                        id={"cve-open-triage-#{target.id}"}
                        type="button"
                        phx-click="open_triage"
                        phx-value-target={target.id}
                        phx-disable-with="Opening…"
                        data-confirm="Open the assessment for this package, team and environment? A new case captures local evidence."
                        class="button"
                      >Open assessment</button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section id="cve-priority" class="stack" aria-labelledby="cve-priority-title">
            <h2 id="cve-priority-title">
              Review priority (deterministic policy v{Risk.policy_version()})
            </h2>
            <p class="supporting">
              Scanner severity is never downgraded. Exposure and exploitation evidence only
              raise review attention. Unknown exposure is never treated as safe.
            </p>
            <%= if @risk do %>
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
                No placement-level evidence in this scope, so no priority can be derived.
              </.notice>
            <% end %>
          </section>

          <section id="cve-intel" class="stack" aria-labelledby="cve-intel-title">
            <h2 id="cve-intel-title">Public intelligence (operator-refreshed cache)</h2>
            <.notice id="cve-intel-banner" kind={if @kev_cache.rows > 0, do: "info", else: "warning"}>
              Public intelligence is cached by an explicit, default-off run of <code>mix triage.intel</code>: this request downloads nothing. This advisory's KEV row was
              fetched {cached_at(List.first(@kev_advisories))}; its NVD rows were fetched {cached_at(
                List.first(@nvd_advisories)
              )}. Absence from the cache never means "not known exploited".
            </.notice>
            <dl class="evidence-grid key-value">
              <div>
                <dt>KEV cache</dt>
                <dd id="cve-kev-cache-state">{cache_text(@kev_cache)}</dd>
              </div>
              <div>
                <dt>NVD cache for this advisory</dt>
                <dd id="cve-nvd-cache-state">{cache_text(@nvd_cache)}</dd>
              </div>
            </dl>
            <p :if={@kev_cache.rows == 0} id="cve-kev-cache-empty" class="supporting">
              No KEV advisories are currently cached. The receipt above describes any recorded
              refresh attempt; a missing cache entry is not evidence that this advisory is unexploited.
            </p>
            <p
              :if={@kev_cache.rows > 0 and @nvd_cache.rows == 0}
              id="cve-intel-partial"
              class="supporting"
            >
              KEV is cached as a whole feed; NVD is fetched one advisory at a time, so missing NVD rows
              here mean "not fetched for this advisory", never "no public description exists".
            </p>
            <p>
              KEV cache match: {if @kev_matched?, do: "Yes", else: "No cached KEV entry"} · NVD entries: {length(
                @nvd_advisories
              )}
            </p>
            <ul :if={@kev_advisories != []} id="cve-kev-list">
              <li :for={a <- @kev_advisories}>
                <.timestamp value={a.published_at} /> · {a.summary || "no summary cached"}
                <p :if={a.required_action} id={"cve-kev-action-#{a.id}"}>
                  Required action: {a.required_action}
                </p>
                <p :if={a.due_date} id={"cve-kev-due-#{a.id}"}>
                  Remediation due <.timestamp value={a.due_date} />
                </p>
                <p :if={a.known_ransomware} id={"cve-kev-ransomware-#{a.id}"} class="supporting">
                  CISA reports known ransomware campaign use.
                </p>
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

          <section id="cve-packages" class="stack" aria-labelledby="cve-packages-title">
            <h2 id="cve-packages-title">Affected libraries</h2>
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
                    <%= if linkable?(o.package_name) do %>
                      <.link
                        id={"cve-package-link-#{o.id}"}
                        navigate={inventory_path(@scope, o.package_name)}
                      >{o.package_name}</.link>
                    <% else %>
                      <span>{o.package_name}</span>
                    <% end %>
                  </td>
                  <td><code>{o.package_version}</code></td>
                  <td>{o.fix || "Not reported"}</td>
                  <td>{o.severity || "Not reported"}</td>
                  <td>{occurrence_state(o)}</td>
                </tr>
              </tbody>
            </table>
          </section>

          <section id="cve-placements" class="stack" aria-labelledby="cve-placements-title">
            <h2 id="cve-placements-title">Placements, exposure and priority</h2>
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
            <p class="supporting">
              Exposure is operator-declared evidence. Missing evidence stays unknown — never safe.
              Each row's priority uses that image's own occurrences and this placement's exposure,
              and escalates when the advisory has a cached KEV entry.
            </p>
          </section>

          <section id="cve-lifecycle" class="stack" aria-labelledby="cve-lifecycle-title">
            <h2 id="cve-lifecycle-title">Lifecycle observations</h2>
            <ul id="cve-lifecycle-list">
              <li :for={o <- @detail.occurrences} id={"cve-lifecycle-#{o.id}"}>
                {o.package_name} <code>{o.package_version}</code>: first seen
                <.timestamp value={o.first_seen} /> · last seen <.timestamp value={o.last_seen} />
                <span :if={o.resolved_at}>· no longer observed <.timestamp value={o.resolved_at} /></span>
                · reopened {o.reopen_count} {plural(o.reopen_count, "time", "times")}
              </li>
            </ul>
          </section>
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
