defmodule TriageWeb.DailyComponents do
  @moduledoc "CVE detection and action history, with explicit response timing."
  use TriageWeb, :html

  attr :days, :list, required: true
  attr :has_more?, :boolean, default: false
  attr :next_before, :string, default: nil
  attr :earlier?, :boolean, default: false
  attr :total_cves, :integer, default: 0
  attr :event_count, :integer, default: 0
  attr :params, :map, default: %{}

  def panel(assigns) do
    ~H"""
    <section id="daily-feed" aria-labelledby="cve-timeline-title">
      <header class="daily-header">
        <div>
          <h1 id="cve-timeline-title">Timeline</h1>
          <p id="cve-timeline-help" class="daily-description">
            One history per CVE: detection first, then the actions taken and the time to first action.
          </p>
        </div>
        <p class="daily-meta">{@total_cves} CVEs · latest activity first · all times UTC</p>
      </header>
      <details id="timeline-timing-help" class="timeline-timing-help">
        <summary>How response time is measured</summary>
        <p>
          Time to first action runs from the first recorded detection to the first saved decision
          on any deployment. Each action shows its scope. A whitelist, ticket, or work request
          counts as a response; it does not confirm a fix or mean every deployment was handled.
          Later detections and expired whitelists stay in the history without resetting this timer.
          A fix marked by a reviewer and a later scan that no longer detects a finding are separate
          events. A shared action across deployments appears once with all its scopes.
        </p>
      </details>
      <div class="timeline-page-summary">
        <span>{@event_count} recorded steps · each CVE history runs oldest to newest</span>
        <button :if={@earlier?} id="timeline-latest" type="button" phx-click="daily-latest">Back to latest activity</button>
      </div>
      <div :if={@days == []} class="daily-empty">
        <h2>No CVE activity recorded{if @earlier?, do: " before this point", else: " yet"}</h2>
        <p>Recorded detections and saved review actions will appear here.</p>
      </div>
      <div :if={@days != []} class="daily-list">
        <article :for={day <- @days} class="daily-day" id={"day-#{Date.to_iso8601(day.date)}"}>
          <div class="day-heading">
            <span>Last activity
            <time datetime={Date.to_iso8601(day.date)}>{Calendar.strftime(day.date, "%B %d, %Y")}</time></span>
            <span class="day-count">{day.count} CVE{if day.count != 1, do: "s", else: ""}</span>
          </div>
          <ul class="day-cves">
            <li
              :for={entry <- day.cves}
              class="day-cve"
              id={"daily-#{entry.cve}"}
            >
              <div class="cve-line">
                <.link
                  class="cve-id"
                  patch={
                    TriageWeb.WorkspaceLive.review_path(
                      Map.drop(@params, ~w(team environment)),
                      entry.cve
                    )
                  }
                >{entry.cve}</.link>
                <span class={"cve-sev severity-#{String.downcase(entry.severity)}"}>{entry.severity}</span>
                <span
                  :if={String.starts_with?(entry.description, "FICTIONAL")}
                  class="timeline-sample"
                >Demo sample</span>
              </div>
              <p :if={entry.packages != ""} class="cve-pkg">{entry.packages}</p>
              <details class="timeline-advisory">
                <summary>Advisory description</summary>
                <p class="cve-desc">{entry.description}</p>
              </details>
              <dl class="timeline-response" aria-label={"Response timing for #{entry.cve}"}>
                <div>
                  <dt>First detected</dt>
                  <dd><.recorded_time value={entry.first_detected_at} /></dd>
                </div>
                <div>
                  <dt>First action · any deployment</dt>
                  <dd :if={entry.first_action}>
                    <.recorded_time value={entry.first_action.at} />
                  </dd>
                  <dd :if={is_nil(entry.first_action)} class="timeline-waiting">
                    Awaiting first action
                  </dd>
                </div>
                <div>
                  <dt>
                    {if entry.first_action,
                      do: "Time to first action",
                      else: "Waiting for first action"}
                  </dt>
                  <dd class={if entry.first_action, do: "timeline-duration", else: "timeline-waiting"}>
                    {duration(
                      if entry.first_action, do: entry.response_seconds, else: entry.waiting_seconds
                    )}
                  </dd>
                </div>
              </dl>
              <ol class="timeline-events" aria-label={"Recorded activity for #{entry.cve}"}>
                <li
                  :for={event <- entry.events}
                  id={"timeline-event-#{event.source}-#{event.id}"}
                  class={["timeline-event", "timeline-event-#{event.source}"]}
                >
                  <time class="timeline-event-time" datetime={DateTime.to_iso8601(event.occurred_at)}>
                    <span>{Calendar.strftime(event.occurred_at, "%d %b %Y")}</span>
                    <span>{Calendar.strftime(event.occurred_at, "%H:%M:%S")}</span>
                  </time>
                  <div class="timeline-event-body">
                    <div class="timeline-event-heading">
                      <strong>{event_label(event)}</strong>
                      <span
                        :if={event.kind != "detected" and not is_nil(event.elapsed_seconds)}
                        class="timeline-elapsed"
                      >{duration(event.elapsed_seconds)} after detection</span>
                    </div>
                    <p :if={event.actor} class="timeline-event-scope">By {event.actor}</p>
                    <p :if={length(event.scopes) == 1} class="timeline-event-scope">
                      {hd(event.scopes)}
                    </p>
                    <details :if={length(event.scopes) > 1} class="timeline-event-scopes">
                      <summary>
                        {length(event.scopes)} {if event.source == "decision",
                          do: "deployment scopes",
                          else: "package / image scopes"}
                      </summary>
                      <ul>
                        <li :for={scope <- event.scopes}>{scope}</li>
                      </ul>
                    </details>
                    <p :if={event.last_recorded_at != event.occurred_at} class="timeline-event-note">
                      All scopes recorded by <.recorded_time value={event.last_recorded_at} />.
                    </p>
                    <p :if={event.reason not in [nil, ""]} class="timeline-event-reason">
                      {event.reason}
                    </p>
                    <p :if={event.expires_at} class="timeline-event-expiry">
                      {if event.kind == "accepted_risk",
                        do: "Whitelist expires",
                        else: "Decision expires"}
                      <.recorded_time value={event.expires_at} />
                    </p>
                    <p
                      :if={event.source == "decision" and is_nil(event.elapsed_seconds)}
                      class="timeline-event-note"
                    >
                      Response time unavailable: the detection date is missing or later than this action.
                    </p>
                  </div>
                </li>
              </ol>
            </li>
          </ul>
        </article>
      </div>
      <div :if={@has_more?} class="daily-more">
        <p>Each CVE’s recorded history stays together on one page.</p>
        <button
          id="timeline-earlier"
          type="button"
          phx-click="daily-prev"
          phx-value-before={@next_before}
        >
          More CVE histories
        </button>
      </div>
    </section>
    """
  end

  attr :value, :any, required: true

  defp recorded_time(assigns) do
    ~H"""
    <time :if={@value} datetime={DateTime.to_iso8601(@value)}>{Calendar.strftime(
      @value,
      "%d %b %Y, %H:%M:%S UTC"
    )}</time>
    <span :if={is_nil(@value)}>Detection date unknown</span>
    """
  end

  defp event_label(%{kind: "accepted_risk", repeated?: true}), do: "Whitelist updated"
  defp event_label(%{kind: "fixed", repeated?: true}), do: "Fix updated"

  defp event_label(%{kind: "detected", elapsed_seconds: seconds})
       when is_integer(seconds) and seconds > 0,
       do: "Detected in an additional package / image"

  defp event_label(%{kind: kind}), do: event_label(kind)
  defp event_label("detected"), do: "Detected"
  defp event_label("reopened"), do: "Detected again"
  defp event_label("resolved"), do: "No longer detected (scanner observation)"
  defp event_label("accepted_risk"), do: "Whitelisted"
  defp event_label("fixed"), do: "Fix marked by reviewer"
  defp event_label("not_affected"), do: "Marked not affected"
  defp event_label("create_ticket"), do: "Ticket created"
  defp event_label("investigate"), do: "Investigation requested"
  defp event_label("request_remediation"), do: "Remediation requested"
  defp event_label("request_verification"), do: "Verification requested"
  defp event_label("mitigated"), do: "Mitigation reported"
  defp event_label(_), do: "Decision recorded"

  defp duration(nil), do: "Unknown"
  defp duration(seconds) when seconds < 60, do: "Less than 1 min"
  defp duration(seconds) when seconds < 3600, do: "#{div(seconds, 60)} min"

  defp duration(seconds) when seconds < 86_400,
    do: "#{div(seconds, 3600)} h #{div(rem(seconds, 3600), 60)} min"

  defp duration(seconds) do
    minutes = div(rem(seconds, 3600), 60)
    base = "#{div(seconds, 86_400)} d #{div(rem(seconds, 86_400), 3600)} h"
    if minutes == 0, do: base, else: base <> " #{minutes} min"
  end
end
