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
  alias TriageWeb.UIComponents

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
          />

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
            <.notice id="cve-intel-banner" kind="info">
              Cached via an explicit run of <code>mix triage.intel</code>. KEV cache: {cached_at(
                List.first(@kev_advisories)
              )}; NVD cache: {cached_at(List.first(@nvd_advisories))}. Absence from the cache never means
              "not known exploited".
            </.notice>
            <p>
              KEV cache match: {if @kev_matched?, do: "Yes", else: "No cached entry"} · NVD entries: {length(
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
                  <td>{o.package_name}</td>
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
