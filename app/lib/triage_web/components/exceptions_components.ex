defmodule TriageWeb.ExceptionsComponents do
  @moduledoc """
  T06: compact read-only Exceptions register. Projects effective accepted-risk
  and legacy whitelist records with their exact source identity. No fake
  not-affected assessment is writable from here (T07 adds typed semantics).
  """
  use TriageWeb, :html

  attr :decisions, :list, required: true
  attr :params, :map, required: true

  def exceptions_register(assigns) do
    ~H"""
    <section class="panel" id="exceptions-register" aria-label="Exceptions register">
      <header class="section-header">
        <h2 id="exceptions-title">Exceptions</h2>
        <p class="supporting">
          Risk-acceptance records with their exact scope, rationale and validity.
          A closed register item does not verify remediation or remove a finding.
        </p>
      </header>

      <div class="filter-summary">
        <strong id="exceptions-count" role="status">{length(@decisions)} exception records</strong>
        <span class="spacer" /><span>Read-only projection · no new assessment from this view</span>
      </div>

      <div class="table-wrap" tabindex="0" role="region" aria-label="Exception records">
        <table id="exceptions-table" class="data-table">
          <caption class="sr-only">
            Recorded exceptions. Each row is one decision record with its exact
            scope, reviewer, and validity boundary. Source identity is preserved.
          </caption>
          <thead>
            <tr>
              <th>Advisory</th><th>Scope</th><th>Type</th><th>Rationale</th><th>Reviewer</th><th>
                Review / expiry
              </th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={d <- @decisions} id={"exception-#{d.id}"}>
              <td>
                <.link class="cve-link" patch={TriageWeb.WorkspaceLive.review_path(@params, d.cve)}>{d.cve}</.link>
              </td>
              <td>{scope_label(d)}</td>
              <td>{d.label}</td>
              <td class="long-value">{d.reason || "No rationale recorded (legacy record)"}</td>
              <td>{d.actor}</td>
              <td>{expiry_label(d)}</td>
              <td>{status_label(d)}</td>
            </tr>
          </tbody>
        </table>
        <div :if={@decisions == []} id="exceptions-empty" class="empty">
          <h2>No exception records</h2>
          <p>
            No risk-acceptance decisions have been recorded in the last year.
            This does not mean the inventory is safe or verified.
          </p>
        </div>
      </div>
    </section>
    """
  end

  defp scope_label(%{placement_id: nil}),
    do: "Legacy global (whole advisory)"

  defp scope_label(d) do
    target = d.metadata["target"] || %{}

    if target["team"] || target["environment"] do
      "#{target["team"] || "unknown team"} · #{target["environment"] || "unknown environment"} · placement #{d.placement_id}"
    else
      "Placement #{d.placement_id} · historical scope"
    end
  end

  defp expiry_label(%{expires_at: nil}),
    do: "No expiry (legacy record)"

  defp expiry_label(%{expires_at: expires_at} = d) do
    boundary =
      if d.metadata["expiry_boundary"] == "exclusive", do: "exclusive", else: "legacy inclusive"

    "#{Calendar.strftime(expires_at, "%Y-%m-%d %H:%M UTC")} (#{boundary})"
  end

  defp status_label(%{state: :active}), do: "Valid"
  defp status_label(%{state: :expired}), do: "Expired"
  defp status_label(%{state: :pending}), do: "Pending"
  defp status_label(_), do: "Unknown"
end
