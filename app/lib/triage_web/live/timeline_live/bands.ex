defmodule TriageWeb.TimelineLive.Bands do
  @moduledoc """
  The day-band waterfall: days stack newest first and each recorded observation
  is an arrow on that day's track.

  Every arrow shape, connector and badge here reports a recorded row. A glyph is
  never the only carrier of meaning: each one has a text equivalent, and a
  connector means no more than "the same CVE also has a recorded observation on
  the adjacent day".
  """

  use TriageWeb, :html

  alias TriageWeb.FindingFilters
  alias TriageWeb.TimelineFilters

  attr :days, :list, required: true
  attr :filters, :map, required: true

  def waterfall(assigns) do
    ~H"""
    <section id="tl-bands" class="tl-section" aria-labelledby="tl-bands-title">
      <div class="section-header">
        <h2 id="tl-bands-title">Recorded observations by day</h2>
        <p class="supporting">
          Newest day first. Days with no recorded observation are shown explicitly.
          A connector joins a CVE that is recorded on two adjacent days; it is not a
          claim that the CVE was present in between.
        </p>
      </div>

      <ol id="tl-band-list" class="tl-band-list">
        <li
          :for={day <- @days}
          id={"tl-band-" <> day.iso_date}
          class={["tl-band", band_class(day)]}
        >
          <div class="tl-band-date">
            <h3 class="tl-band-label"><time datetime={day.iso_date}>{day.label}</time></h3>
            <p class="supporting tl-band-counts">{day_counts(day)}</p>
          </div>

          <div class="tl-band-track">
            <p
              :if={not day.observed?}
              id={"tl-band-empty-" <> day.iso_date}
              class="tl-band-none supporting"
            >
              No recorded observation on this day. An empty day is not a clean day.
            </p>

            <ul :if={day.observed?} class="tl-rows">
              <li :for={row <- day.rows} id={"tl-row-" <> row_key(row, day)} class="tl-row">
                <span class={["tl-arrow", arrow_class(row)]} aria-hidden="true">{arrow_glyph(row)}</span>
                <span class="sr-only">{arrow_text(row)}</span>
                <span
                  :if={row.continued_from?}
                  class="tl-connector tl-connector-up"
                  aria-hidden="true"
                ></span>
                <span :if={row.continues?} class="tl-connector tl-connector-down" aria-hidden="true"></span>

                <div class="tl-row-main">
                  <p class="tl-row-title">
                    <strong>{row.cve}</strong>
                    <.status_badge label={display_value(row.severity)} kind="severity" />
                    <span class="supporting">{event_label(row.kind)}</span>
                  </p>
                  <p class="supporting">
                    {row.package_name} <code>{row.package_version}</code>
                    <span :if={row.fix}> · recorded fix {row.fix}</span>
                    <span> · recorded observation time <.timestamp value={row.occurred_at} /></span>
                  </p>
                  <p class="supporting">
                    {state_label(row)}<span :if={row.suppressed}> · suppression flag currently set from the imported scanner data (no recorded date or author)</span>
                  </p>
                </div>

                <div class="tl-row-actions">
                  <.link
                    id={"tl-open-" <> row_key(row, day)}
                    patch={TimelineFilters.path(@filters, %{cve: row.cve})}
                    class="button button-secondary"
                  >
                    Timeline detail
                  </.link>
                  <.link
                    id={"tl-advisory-" <> row_key(row, day)}
                    navigate={FindingFilters.advisory_path(row.cve, @filters)}
                    class="button button-secondary"
                  >
                    Advisory page
                  </.link>
                </div>
              </li>
            </ul>

            <p :if={day.truncated_count > 0} class="supporting">
              {day.truncated_count} further recorded event(s) on this day are not shown.
            </p>
          </div>
        </li>
      </ol>
    </section>
    """
  end

  defp row_key(row, _day), do: Integer.to_string(row.event_id)

  defp band_class(%{observed?: true}), do: "tl-band-observed"
  defp band_class(%{observed?: false, judged_count: judged}) when judged > 0, do: "tl-band-judged"
  defp band_class(_day), do: "tl-band-empty"

  defp day_counts(%{event_count: 0, judged_count: 0}), do: "No recorded activity on this day"

  defp day_counts(day) do
    [
      count_phrase(day.event_count, "recorded event", "recorded events"),
      count_phrase(day.new_count, "first observation", "first observations"),
      count_phrase(day.resolved_count, "no-longer-observed event", "no-longer-observed events"),
      count_phrase(day.reopened_count, "re-observation", "re-observations"),
      count_phrase(day.judged_count, "recorded assessment", "recorded assessments")
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" · ")
  end

  defp count_phrase(0, _one, _many), do: nil
  defp count_phrase(1, one, _many), do: "1 " <> one
  defp count_phrase(count, _one, many), do: "#{count} " <> many

  defp event_label("appeared"), do: "first recorded observation"
  defp event_label("resolved"), do: "no longer observed in local inventory"
  defp event_label("reopened"), do: "observed again locally"
  defp event_label(_other), do: "unrecognized lifecycle event"

  defp arrow_glyph(%{suppressed: true}), do: "⊘"
  defp arrow_glyph(%{kind: "resolved"}), do: "╢"
  defp arrow_glyph(%{kind: "reopened"}), do: "↺"
  defp arrow_glyph(_row), do: "▶"

  defp arrow_class(%{suppressed: true}), do: "tl-arrow-suppressed"
  defp arrow_class(%{kind: "resolved"}), do: "tl-arrow-ended"
  defp arrow_class(%{kind: "reopened"}), do: "tl-arrow-reopened"
  defp arrow_class(_row), do: "tl-arrow-open"

  defp arrow_text(%{suppressed: true} = row),
    do: event_label(row.kind) <> "; suppression flag currently set"

  defp arrow_text(row), do: event_label(row.kind)

  defp state_label(%{state: :open, reopened?: true}),
    do: "Currently open in local inventory; previously recorded as no longer observed"

  defp state_label(%{state: :open}), do: "Currently open in local inventory"

  defp state_label(%{state: :no_longer_observed}),
    do: "Currently no longer observed in local inventory"
end
