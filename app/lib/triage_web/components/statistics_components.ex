defmodule TriageWeb.StatisticsComponents do
  @moduledoc """
  The Statistics page: how long CVEs took to handle and how each deployment was
  handled, over a chosen period, with a CSV export of the same rows. The
  numbers come from `Triage.Statistics`; this module only presents them.
  """
  use TriageWeb, :html
  import TriageWeb.WorkspaceComponents, only: [format_date: 1, severity: 1]
  alias TriageWeb.WorkspaceLive, as: Routes

  @period_labels [
    {"30d", "30 days"},
    {"90d", "90 days"},
    {"12m", "12 months"},
    {"all", "All time"}
  ]
  # A fixed order, so the bars compare across periods.
  @outcome_order [
    "Whitelisted",
    "Marked fixed",
    "Fixed, not yet confirmed",
    "Fixed, confirmed by scan",
    "Ticket created",
    "Disappeared on its own"
  ]
  @shown_rows 100

  @doc "The URL `period` value, defaulting to the last 90 days."
  def period(params),
    do:
      if(params["period"] in Map.keys(Triage.Statistics.periods()),
        do: params["period"],
        else: "90d"
      )

  attr :report, :map, required: true
  attr :params, :map, required: true

  def panel(assigns) do
    assigns =
      assign(assigns,
        period: period(assigns.params),
        summary: assigns.report.summary,
        outcomes: outcome_bars(assigns.report.summary.outcomes)
      )

    ~H"""
    <section id="statistics" class="statistics" aria-labelledby="statistics-title">
      <header class="statistics-head">
        <div>
          <h1 id="statistics-title">Statistics</h1>
          <p class="statistics-lede">
            How long CVEs took to handle and how each was handled, for the team and environment chosen above.
          </p>
        </div>
        <a id="statistics-export" class="statistics-export" href={export_path(@params, @period)}>
          Download CSV
        </a>
      </header>

      <nav class="list-tabs statistics-periods" aria-label="Period">
        <.link
          :for={{value, label} <- period_labels()}
          id={"statistics-period-#{value}"}
          patch={Routes.workspace_path(@params, %{"page" => "statistics", "period" => value})}
          class={["list-tab", @period == value && "active"]}
          aria-current={if @period == value, do: "page"}
        >{label}</.link>
      </nav>

      <dl class="stat-tiles">
        <div class="stat-tile">
          <dt>Open now</dt>
          <dd class="stat-value">{@summary.open}</dd>
          <dd class="stat-note">
            {if @summary.oldest_open_days,
              do: "Oldest open for #{days(@summary.oldest_open_days)}",
              else: "Nothing waiting for a decision"}
          </dd>
        </div>
        <div class="stat-tile">
          <dt>Handled {period_phrase(@period)}</dt>
          <dd class="stat-value">{@summary.handled}</dd>
          <dd class="stat-note">CVEs with every deployment handled</dd>
        </div>
        <div class="stat-tile">
          <dt>Median time to first action</dt>
          <dd class="stat-value">{median(@summary.median_days_to_first_action)}</dd>
          <dd class="stat-note">From first observed to the first decision</dd>
        </div>
        <div class="stat-tile">
          <dt>Median time to handle</dt>
          <dd class="stat-value">{median(@summary.median_days_to_handle)}</dd>
          <dd class="stat-note">Until every deployment was handled</dd>
        </div>
      </dl>

      <section class="panel statistics-card" aria-labelledby="statistics-outcomes-title">
        <h2 id="statistics-outcomes-title">How deployments were handled {period_phrase(@period)}</h2>
        <ul :if={@outcomes != []} id="statistics-outcomes" class="outcome-bars">
          <li :for={bar <- @outcomes}>
            <span class="outcome-label">{bar.label}</span>
            <span class="outcome-track">
              <span
                class="outcome-bar"
                style={"width: #{bar.width}%"}
                title={"#{bar.label}: #{bar.count} of #{bar.total} (#{bar.share}%)"}
              ></span>
            </span>
            <span class="outcome-value">{bar.count} <span class="outcome-share">{bar.share}%</span></span>
          </li>
        </ul>
        <p :if={@outcomes == []} class="statistics-empty">
          Nothing was handled {period_phrase(@period)}.
        </p>
      </section>

      <details id="statistics-help" class="statistics-help">
        <summary>How these numbers are counted</summary>
        <dl>
          <dt>First observed</dt>
          <dd>When the scanner first recorded the CVE on a deployment, as on the Timeline.</dd>
          <dt>First action</dt>
          <dd>
            The first decision after that: Whitelisted, Marked fixed or Ticket created, with who made it.
            Older records may show other decisions, such as Remediation requested.
          </dd>
          <dt>No longer observed</dt>
          <dd>
            When the scanner stopped reporting the CVE on that deployment, or the deployment was retired.
          </dd>
          <dt>How it was handled</dt>
          <dd>
            The first action, or <strong>Disappeared on its own</strong>
            when the scanner stopped reporting it before any decision (for example a vendor update or a new image).
            A fix that the scanner then stopped reporting is <strong>Fixed, confirmed by scan</strong>.
          </dd>
          <dt>Time to handle</dt>
          <dd>
            A CVE is handled once every deployment is. The period counts CVEs handled in it; open CVEs are always listed,
            and one handled in the period that needs a decision again appears in both tables. Days, medians included,
            are whole days, counted down.
          </dd>
        </dl>
      </details>

      <section class="panel statistics-card" aria-labelledby="statistics-open-title">
        <h2 id="statistics-open-title">
          Open now <span class="statistics-count">{length(@report.open)}</span>
        </h2>
        <div :if={@report.open != []} class="table-wrap">
          <table id="statistics-open" class="data-table statistics-table">
            <thead>
              <tr>
                <th>CVE</th><th>Severity</th><th>Package</th><th>First observed</th><th>Open for</th><th>
                  Needs a decision
                </th><th>First action</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={row <- Enum.take(@report.open, shown_rows())}>
                <td>
                  <.link
                    class="statistics-cve"
                    patch={Routes.review_path(Map.take(@params, ~w(team environment)), row.cve)}
                  >
                    {row.cve}
                  </.link>
                </td>
                <td><.severity value={row.severity} /></td>
                <td><.packages list={row.packages} /></td>
                <td class="date">{date(row.observed_at)}</td>
                <td class="num">{days(row.days_open)}</td>
                <td>{row.open_deployments} of {row.deployments}</td>
                <td><.action action={row.first_action} /></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p :if={@report.open == []} class="statistics-empty">No CVE needs a decision.</p>
        <p :if={length(@report.open) > shown_rows()} class="statistics-more">
          Showing {shown_rows()} of {length(@report.open)}. The CSV has every row.
        </p>
      </section>

      <section class="panel statistics-card" aria-labelledby="statistics-handled-title">
        <h2 id="statistics-handled-title">
          Handled {period_phrase(@period)}
          <span class="statistics-count">{length(@report.handled)}</span>
        </h2>
        <div :if={@report.handled != []} class="table-wrap">
          <table id="statistics-handled" class="data-table statistics-table">
            <thead>
              <tr>
                <th>CVE</th><th>Severity</th><th>Package</th><th>First observed</th><th>
                  First action
                </th><th>Time to first action</th><th>Handled</th><th>Time to handle</th><th>How</th><th>
                  Now
                </th>
              </tr>
            </thead>
            <tbody>
              <tr :for={row <- Enum.take(@report.handled, shown_rows())}>
                <td class="statistics-cve">{row.cve}</td>
                <td><.severity value={row.severity} /></td>
                <td><.packages list={row.packages} /></td>
                <td class="date">{date(row.observed_at)}</td>
                <td><.action action={row.first_action} /></td>
                <td class="num">{days(row.days_to_first_action)}</td>
                <td class="date">{date(row.handled_at)}</td>
                <td class="num">{days(row.days_to_handle)}</td>
                <td>{row.outcome}</td>
                <td>{row.current_state}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p :if={@report.handled == []} class="statistics-empty">
          Nothing was handled {period_phrase(@period)}.
        </p>
        <p :if={length(@report.handled) > shown_rows()} class="statistics-more">
          Showing {shown_rows()} of {length(@report.handled)}. The CSV has every row.
        </p>
      </section>
    </section>
    """
  end

  attr :list, :list, required: true

  defp packages(%{list: []} = assigns), do: ~H"—"

  defp packages(assigns) do
    ~H"""
    <span title={Enum.join(@list, ", ")}>{hd(@list)}<span
      :if={length(@list) > 1}
      class="statistics-more-packages"
    > +{length(@list) - 1}</span></span>
    """
  end

  @doc "The CSV download for the current team, environment and period."
  def export_path(params, period) do
    query =
      params
      |> Map.take(~w(team environment))
      |> Map.put("period", period)
      |> Map.filter(fn {_key, value} -> is_binary(value) and value != "" end)
      |> URI.encode_query()

    "/statistics/export.csv?" <> query
  end

  defp period_labels, do: @period_labels
  defp shown_rows, do: @shown_rows

  defp period_phrase("30d"), do: "in the last 30 days"
  defp period_phrase("12m"), do: "in the last 12 months"
  defp period_phrase("all"), do: "so far"
  defp period_phrase(_period), do: "in the last 90 days"

  defp outcome_bars(outcomes) when map_size(outcomes) == 0, do: []

  defp outcome_bars(outcomes) do
    total = outcomes |> Map.values() |> Enum.sum()
    most = outcomes |> Map.values() |> Enum.max()
    extra = outcomes |> Map.keys() |> Enum.reject(&(&1 in @outcome_order)) |> Enum.sort()

    for label <- @outcome_order ++ extra, count = Map.get(outcomes, label, 0), count > 0 do
      %{
        label: label,
        count: count,
        total: total,
        share: round(count * 100 / total),
        width: Float.round(count * 100 / most, 1)
      }
    end
  end

  defp date(nil), do: "—"
  defp date(value), do: format_date(value)

  defp days(nil), do: "—"
  defp days(0), do: "same day"
  defp days(1), do: "1 day"
  defp days(n) when is_integer(n), do: "#{n} days"

  # Whole days, counted down like every other duration on the page and in the CSV.
  defp median(nil), do: "—"
  defp median(value), do: value |> trunc() |> days()

  attr :action, :map, default: nil

  defp action(%{action: nil} = assigns), do: ~H"None yet"

  defp action(assigns) do
    ~H"""
    {@action.label}<span class="subline">{format_date(@action.at)}{if @action.by,
      do: " · #{@action.by}"}</span>
    """
  end
end
