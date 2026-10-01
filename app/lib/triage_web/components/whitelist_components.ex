defmodule TriageWeb.WhitelistComponents do
  @moduledoc """
  The whitelist overview dialog, opened by the quiet button on the Triage
  toolbar. It lists what is whitelisted, in the Azure DevOps repository file
  and in Triage, and until when. Each end date carries a status bar: green
  while there is time, orange when it ends within 30 days, red in the last
  week or once it has ended. The status is always also written out. Rows and
  numbers come from `Triage.RepoWhitelist`.
  """
  use TriageWeb, :html
  import TriageWeb.WorkspaceComponents, only: [format_date: 1, severity: 1, team_name: 1, time: 1]
  alias Triage.RepoWhitelist
  alias TriageWeb.WorkspaceLive, as: Routes

  @shown_rows 300
  @shown_missing 50
  # Days left at which the status bar is full.
  @full_bar_days 90

  attr :state, :map, required: true
  attr :params, :map, required: true

  def dialog(assigns) do
    overview = assigns.state.overview

    assigns =
      assigns
      |> assign(:overview, overview)
      |> assign(:scope, Map.take(assigns.params, ~w(team environment)))
      |> assign(:compared, overview != nil and overview.repository.state == :loaded)

    ~H"""
    <dialog
      id="whitelist-overview"
      class="confirm wide"
      phx-hook="WorkspaceDialog"
      data-close-event="close-repo-whitelist"
      aria-labelledby="whitelist-overview-title"
    >
      <div class="confirmation-layout">
        <header class="modal-head whitelist-head">
          <h2 id="whitelist-overview-title">Whitelist overview</h2>
          <p class="whitelist-scope">{scope_label(@scope)}</p>
        </header>
        <div class="modal-body whitelist-body" aria-busy={to_string(@state.loading)}>
          <p :if={@state.loading and is_nil(@overview)} id="whitelist-loading" role="status">
            Reading the whitelist…
          </p>
          <p :if={@state.failed} id="whitelist-failed" class="whitelist-alert" role="alert">
            The overview could not be loaded. Try Read again.
          </p>
          <div :if={@overview} class="whitelist-overview">
            <.source repository={@overview.repository} />
            <.facts counts={@overview.counts} missing={@overview.missing} compared={@compared} />
            <.legend open_ended={open_ended?(@overview.rows)} />
            <.entries rows={@overview.rows} compared={@compared} scope={@scope} />
            <.missing :if={@overview.missing} missing={@overview.missing} scope={@scope} />
          </div>
        </div>
        <footer class="modal-foot">
          <button
            id="whitelist-reload"
            type="button"
            phx-click="repo-whitelist"
            phx-value-reload="true"
            disabled={@state.loading}
          >
            {if @state.loading, do: "Reading…", else: "Read again"}
          </button>
          <button id="whitelist-close" type="button" phx-click="close-repo-whitelist">Close</button>
        </footer>
      </div>
    </dialog>
    """
  end

  defp open_ended?(rows),
    do: Enum.any?(rows, &(&1.repository != nil and &1.repository.status == :open_ended))

  defp scope_label(scope) do
    team = if scope["team"] in [nil, ""], do: "All teams", else: team_name(scope["team"])

    environment =
      if scope["environment"] in [nil, ""], do: "all environments", else: scope["environment"]

    "#{team}, #{environment}"
  end

  ## Where the repository list came from

  attr :repository, :map, required: true

  defp source(%{repository: %{state: :loaded}} = assigns) do
    ~H"""
    <p id="whitelist-source" class="whitelist-source">
      <span class="whitelist-source-label">Repository list</span>
      <a :if={@repository[:url]} href={@repository.url} target="_blank" rel="noopener noreferrer">
        {@repository.label}
      </a>
      <span :if={!@repository[:url]}>{@repository.label}</span>
      <span class="whitelist-source-meta">
        Read {time(@repository.read_at)}{commit(@repository.commit)}
      </span>
    </p>
    <p :if={@repository.total == 0} id="whitelist-empty-file" class="whitelist-alert" role="alert">
      The file was read, but no CVE id was found in it. Check that ADO_WHITELIST_PATH points to the whitelist.
    </p>
    """
  end

  defp source(%{repository: %{state: :not_configured}} = assigns) do
    ~H"""
    <p id="whitelist-source" class="whitelist-source whitelist-setup">
      <span class="whitelist-source-label">Repository list</span>
      Not connected. This shows what is whitelisted in Triage. To compare it with the list kept in Azure DevOps, an administrator sets
      <code>ADO_WHITELIST_REPO</code>
      and <code>ADO_WHITELIST_PATH</code>
      on the server.
    </p>
    """
  end

  defp source(assigns) do
    ~H"""
    <div id="whitelist-source" class="whitelist-alert" role="alert">
      <p><strong>The repository list could not be read.</strong> {@repository.message}</p>
      <p :if={@repository[:label]} class="whitelist-alert-file">{@repository.label}</p>
      <p>What is whitelisted in Triage is shown below.</p>
    </div>
    """
  end

  defp commit(nil), do: ""
  defp commit(id), do: ", commit " <> String.slice(id, 0, 8)

  ## The numbers

  attr :counts, :map, required: true
  attr :missing, :map, default: nil
  attr :compared, :boolean, required: true

  defp facts(assigns) do
    ~H"""
    <dl id="whitelist-facts" class="whitelist-facts">
      <div :if={@compared}>
        <dt>In the repository list</dt>
        <dd>
          <strong>{@counts.repository}</strong>
          <span>{ending(@counts.expired, @counts.expiring)}</span>
        </dd>
      </div>
      <div>
        <dt>Whitelisted in Triage</dt>
        <dd>
          <strong>{@counts.triage}</strong>
          <span>{ending(0, @counts.triage_expiring)}</span>
        </dd>
      </div>
      <div :if={@missing}>
        <dt>In neither</dt>
        <dd>
          <strong>{@missing.total}</strong>
          <span>{need(@missing.total)} a decision</span>
        </dd>
      </div>
    </dl>
    <ul :if={@compared} id="whitelist-differences" class="whitelist-differences">
      <li class="whitelist-differences-label">Differences</li>
      <li><b>{@counts.triage_only}</b> whitelisted in Triage, not in the list</li>
      <li>
        <b>{@counts.open_in_triage}</b>
        in the list, {need(@counts.open_in_triage)} a decision in Triage
      </li>
      <li><b>{@counts.not_in_findings}</b> in the list, not in current findings</li>
    </ul>
    """
  end

  defp need(1), do: "needs"
  defp need(_many), do: "need"

  defp ending(0, 0), do: "none ends within 30 days"
  defp ending(0, soon), do: "#{soon} #{end_verb(soon)} within 30 days"
  defp ending(ended, 0), do: "#{ended} ended"
  defp ending(ended, soon), do: "#{ended} ended, #{soon} #{end_verb(soon)} within 30 days"

  defp end_verb(1), do: "ends"
  defp end_verb(_many), do: "end"

  attr :open_ended, :boolean, required: true

  defp legend(assigns) do
    assigns = assign(assigns, :days, RepoWhitelist.thresholds())

    ~H"""
    <ul id="whitelist-legend" class="whitelist-legend" aria-label="What the bar colours mean">
      <li class="expiry-ok">
        <span class="expiry-bar"><span style="width: 100%"></span></span>
        More than {@days.soon} days left
      </li>
      <li class="expiry-soon"><span class="expiry-bar"><span style="width: 33%"></span></span>
        {@days.soon} days or fewer</li>
      <li class="expiry-critical"><span class="expiry-bar"><span style="width: 8%"></span></span>
        {@days.critical} days or fewer</li>
      <li class="expiry-expired"><span class="expiry-bar"></span> Ended</li>
      <li :if={@open_ended} class="expiry-open_ended">
        <span class="expiry-bar"></span> No end date
      </li>
    </ul>
    """
  end

  ## What is whitelisted

  attr :rows, :list, required: true
  attr :compared, :boolean, required: true
  attr :scope, :map, required: true

  defp entries(%{rows: []} = assigns) do
    ~H"""
    <p id="whitelist-none" class="whitelist-none">
      Nothing is whitelisted in this team and environment.
    </p>
    """
  end

  defp entries(assigns) do
    assigns = assign(assigns, :shown, Enum.take(assigns.rows, @shown_rows))

    ~H"""
    <table id="whitelist-entries" class={["whitelist-table", @compared && "compared"]}>
      <thead>
        <tr>
          <th scope="col">CVE</th>
          <th :if={@compared} scope="col">Repository list</th>
          <th scope="col">Triage</th>
        </tr>
      </thead>
      <tbody>
        <tr :for={row <- @shown} id={"whitelist-row-#{row.cve}"}>
          <td class="whitelist-cve">
            <.cve cve={row.cve} linked={row.triage.state != :not_observed} scope={@scope} />
            <.severity :if={row.severity} value={row.severity} />
            <span :if={row.packages not in [nil, ""]} class="whitelist-packages">{row.packages}</span>
          </td>
          <td :if={@compared} data-label="Repository list">
            <.listed entry={row.repository} />
          </td>
          <td data-label="Triage">
            <.recorded cell={row.triage} />
          </td>
        </tr>
      </tbody>
    </table>
    <p :if={length(@rows) > length(@shown)} class="whitelist-more">
      Showing the {length(@shown)} that end soonest, of {length(@rows)}.
    </p>
    """
  end

  attr :cve, :string, required: true
  attr :linked, :boolean, required: true
  attr :scope, :map, required: true

  defp cve(%{linked: true} = assigns) do
    ~H"""
    <.link class="statistics-cve" patch={Routes.review_path(@scope, @cve)}>{@cve}</.link>
    """
  end

  defp cve(assigns) do
    ~H"""
    <span class="statistics-cve">{@cve}</span>
    """
  end

  attr :entry, :map, default: nil

  defp listed(%{entry: nil} = assigns) do
    ~H"""
    <span class="whitelist-state">Not in the list</span>
    """
  end

  defp listed(assigns) do
    ~H"""
    <.expiry until={@entry.until} status={@entry.status} days_left={@entry.days_left} />
    <span :if={@entry.reason} class="whitelist-reason" title={@entry.reason}>{@entry.reason}</span>
    <span :if={@entry.occurrences > 1} class="whitelist-note">
      Listed {@entry.occurrences} times, the earliest end date counts
    </span>
    """
  end

  attr :cell, :map, required: true

  defp recorded(%{cell: %{until: %Date{}}} = assigns) do
    ~H"""
    <.expiry until={@cell.until} status={@cell.status} days_left={@cell.days_left} />
    <span :if={@cell.whitelisted < @cell.deployments} class="whitelist-note">
      {partial(@cell)}
    </span>
    """
  end

  defp recorded(assigns) do
    ~H"""
    <span class={["whitelist-state", @cell.state == :needs_decision && "open"]}>{state(@cell)}</span>
    """
  end

  defp partial(cell) do
    covered = "#{cell.whitelisted} of #{cell.deployments} deployments"

    case cell.open do
      0 -> covered
      1 -> covered <> ", 1 needs a decision"
      open -> covered <> ", #{open} need a decision"
    end
  end

  defp state(%{state: :needs_decision}), do: "Needs a decision"
  defp state(%{state: :not_observed}), do: "Not in current findings"
  defp state(%{state: :whitelisted}), do: "Whitelisted, no end date"
  defp state(%{decided: [_ | _] = labels}), do: Enum.join(labels, ", ")
  defp state(_cell), do: "Decided"

  ## One end date: the bar, the date, the time left

  attr :until, :any, required: true
  attr :status, :atom, required: true
  attr :days_left, :any, required: true

  defp expiry(assigns) do
    ~H"""
    <span class={["expiry", "expiry-#{@status}"]}>
      <span class="expiry-bar" aria-hidden="true">
        <span style={"width: #{fill(@days_left)}%"}></span>
      </span>
      <span class="expiry-date">{until(@until, @status)}</span>
      <span :if={@until} class="expiry-left">{left(@days_left)}</span>
    </span>
    """
  end

  # Longer bar, more time: full at `@full_bar_days`, empty once ended.
  defp fill(nil), do: 0
  defp fill(days) when days < 0, do: 0
  defp fill(days), do: days |> Kernel.*(100) |> div(@full_bar_days) |> max(6) |> min(100)

  defp until(nil, _status), do: "No end date"
  defp until(date, :expired), do: "Ended " <> format_date(date)
  defp until(date, _status), do: "Until " <> format_date(date)

  defp left(0), do: "last day today"
  defp left(1), do: "1 day left"
  defp left(-1), do: "1 day ago"
  defp left(days) when days < 0, do: "#{-days} days ago"
  defp left(days), do: "#{days} days left"

  ## What still needs a decision and is in neither

  attr :missing, :map, required: true
  attr :scope, :map, required: true

  defp missing(%{missing: %{total: 0}} = assigns) do
    ~H"""
    <section id="whitelist-missing" class="whitelist-missing">
      <h3>Need a decision, not in the repository list</h3>
      <p class="whitelist-missing-note">
        Every CVE that needs a decision here has an entry in the list that still applies.
      </p>
    </section>
    """
  end

  defp missing(assigns) do
    assigns = assign(assigns, :shown, Enum.take(assigns.missing.rows, @shown_missing))

    ~H"""
    <section id="whitelist-missing" class="whitelist-missing">
      <h3>
        Need a decision, not in the repository list
        <span class="statistics-count">{@missing.total}</span>
      </h3>
      <p class="whitelist-missing-note">
        Open in Triage, and no entry in the list covers them. Most severe first.
      </p>
      <ul class="whitelist-missing-list">
        <li :for={row <- @shown}>
          <.cve cve={row.cve} linked scope={@scope} />
          <.severity value={row.severity} />
          <span class="whitelist-packages">{row.packages}</span>
        </li>
      </ul>
      <p :if={@missing.total > length(@shown)} class="whitelist-more">
        Showing {length(@shown)} of {@missing.total}. The Need a decision list has all of them.
      </p>
    </section>
    """
  end
end
