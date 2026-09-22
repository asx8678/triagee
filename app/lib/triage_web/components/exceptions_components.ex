defmodule TriageWeb.ExceptionsComponents do
  @moduledoc """
  Read-only risk decision history: accepted-risk and not-affected records.
  Expiry status describes each record's time limit, not whether it is the
  current effective decision. Open a CVE in Review to see its current state.
  """
  use TriageWeb, :html

  attr :decisions, :list, required: true
  attr :params, :map, required: true

  def exceptions_register(assigns) do
    ~H"""
    <section class="panel risk-decisions" id="exceptions-register" aria-labelledby="exceptions-title">
      <header class="risk-decisions-header">
        <h1 id="exceptions-title">Risk decisions</h1>
        <p class="supporting">
          Saved decisions to temporarily accept a CVE's risk (whitelist it) or mark it not affected.
          Each record shows the deployments it applies to, the action taken, and the reason.
        </p>
        <p id="risk-decisions-expiry-help" class="risk-decisions-help">
          <strong>What expires?</strong>
          The decision, not the CVE. After expiry, the listed deployments need review again
          unless a newer decision applies. Expiry does not mean the vulnerability is fixed.
        </p>
      </header>

      <div class="filter-summary">
        <strong id="exceptions-count" role="status">{length(@decisions)} risk decision records</strong>
        <span>Last 365 days · newest decisions first</span>
        <span class="spacer" /><span>Open a CVE to review its current status</span>
      </div>

      <div class="table-wrap" tabindex="0" role="region" aria-label="Risk decision history">
        <table id="exceptions-table" class="data-table">
          <caption class="sr-only">
            Risk decision history, including older decisions that may have been replaced.
            Expiry status shows only whether each record's time limit has passed.
          </caption>
          <thead>
            <tr>
              <th scope="col">CVE</th><th scope="col">Applies to</th><th scope="col">Action taken</th><th scope="col">
                Reason
              </th><th scope="col">Decided by</th><th
                scope="col"
                aria-describedby="risk-decisions-expiry-help"
              >
                Expires at (UTC)
              </th><th scope="col">Expiry status</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={d <- @decisions} id={"exception-#{d.id}"}>
              <td>
                <.link class="cve-link" patch={TriageWeb.WorkspaceLive.review_path(@params, d.cve)}>{d.cve}</.link>
              </td>
              <td>{scope_label(d)}</td>
              <td>{d.label}</td>
              <td class="long-value">{d.reason || "No reason saved (older record)"}</td>
              <td>{d.actor}</td>
              <td>
                <time
                  :if={d.expires_at}
                  datetime={DateTime.to_iso8601(d.expires_at)}
                  title={expiry_help(d)}
                >{expiry_label(d)}</time>
                <span :if={is_nil(d.expires_at)}>No expiry set</span>
              </td>
              <td>{status_label(d)}</td>
            </tr>
          </tbody>
        </table>
        <div :if={@decisions == []} id="exceptions-empty" class="empty">
          <h2>No risk decisions recorded</h2>
          <p>
            No whitelist or not-affected decisions were recorded in the last 365 days.
            Open a CVE in Review to assess it and record a decision.
          </p>
          <.link
            id="risk-decisions-open-review"
            patch={TriageWeb.WorkspaceLive.nav_path(@params, "findings")}
          >Go to Review</.link>
        </div>
      </div>
      <p class="risk-decisions-footer">
        This history includes older decisions that may have been replaced. Open a CVE for its current status.
      </p>
    </section>
    """
  end

  defp scope_label(%{placement_id: nil}),
    do: "All deployments for this CVE (older record)"

  defp scope_label(d) do
    target = d.metadata["target"] || %{}

    if target["team"] || target["environment"] do
      "#{target["team"] || "unknown team"} · #{target["environment"] || "unknown environment"} · deployment ##{d.placement_id}"
    else
      "Deployment ##{d.placement_id} · team and environment not recorded"
    end
  end

  defp expiry_label(%{expires_at: expires_at}),
    do: Calendar.strftime(expires_at, "%d %b %Y, %H:%M:%S")

  defp expiry_help(d) do
    if d.metadata["expiry_boundary"] == "exclusive",
      do: "Stops applying at this time (UTC).",
      else: "Older record: remains valid through this time (UTC)."
  end

  defp status_label(%{state: :active, expires_at: nil}), do: "No time limit"
  defp status_label(%{state: :active}), do: "Not expired"
  defp status_label(%{state: :expired}), do: "Expired"
  defp status_label(%{state: :pending}), do: "Not yet in effect"
  defp status_label(_), do: "Unknown"
end
