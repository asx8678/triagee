defmodule TriageWeb.CaseFormat do
  @moduledoc """
  Pure view-model formatting for saved review cases.

  Every stored value degrades to a visible placeholder instead of crashing a
  template. Used by the observation timeline's case history.
  """

  # Timeline = case events + reviews, deterministically ordered (newest
  # first, stable tiebreak on the stream key). Every entry carries the same
  # shape so the template never depends on key presence per type.
  def timeline_entries(data) do
    current_id = data.case.current_snapshot_id
    versions = Map.new(data.snapshots, &{&1.id, &1.version})

    event_entries =
      for event <- data.events do
        %{
          key: "event-#{event.id}",
          type: :event,
          at: event.inserted_at,
          kind: event.kind,
          actor: event.actor,
          case_revision: event.case_revision,
          snapshot_id: event.snapshot_id,
          review_id: event.review_id,
          detail_pairs: detail_pairs(event.detail),
          applicability: nil,
          priority: nil,
          next_action: nil,
          rationale: nil,
          snapshot_version: nil,
          is_stale: false
        }
      end

    review_entries =
      for review <- data.reviews do
        %{
          key: "review-#{review.id}",
          type: :review,
          at: review.inserted_at,
          kind: "review",
          actor: review.actor,
          case_revision: nil,
          snapshot_id: review.snapshot_id,
          review_id: review.id,
          detail_pairs: [],
          applicability: review.applicability,
          priority: review.priority,
          next_action: review.next_action,
          rationale: review.rationale,
          snapshot_version: versions[review.snapshot_id] || review.snapshot_id,
          is_stale: review.snapshot_id != current_id
        }
      end

    (event_entries ++ review_entries)
    |> Enum.sort_by(fn entry -> {-time_key(entry.at), entry.key} end)
  end

  defp detail_pairs(detail) when is_map(detail) do
    detail
    |> Map.keys()
    |> Enum.sort()
    |> Enum.map(fn key -> %{key: safe_text(key), value: safe_text(Map.get(detail, key))} end)
  end

  defp detail_pairs(_other), do: []

  defp safe_text(value) when is_binary(value), do: value
  defp safe_text(value), do: inspect(value)

  defp time_key(%DateTime{} = dt), do: DateTime.to_unix(dt)

  defp time_key(%NaiveDateTime{} = ndt),
    do: :calendar.datetime_to_gregorian_seconds(NaiveDateTime.to_erl(ndt))

  defp time_key(_other), do: 0

  defp text(value) when value in [nil, ""], do: "Not reported"
  defp text(value) when is_binary(value), do: value
  defp text(value), do: inspect(value)

  # The stored keys of the three manual assessment choices and their labels.
  @labels %{
    "affected" => "Affected",
    "not_affected_with_evidence" => "Not affected with evidence",
    "unknown" => "Unknown",
    "expedited_review" => "Expedited review",
    "normal_review" => "Normal review",
    "insufficient_context" => "Insufficient context",
    "investigation" => "Investigation",
    "dependency_update" => "Dependency update",
    "base_image_update" => "Base image update",
    "rebuild_deploy" => "Rebuild and redeploy",
    "mitigation_review" => "Mitigation review",
    "exception_proposal" => "Exception proposal"
  }

  def label(value) do
    case Map.fetch(@labels, value) do
      {:ok, label} -> label
      :error -> event_label(value)
    end
  end

  def event_label("case_opened"), do: "Case opened"
  def event_label("evidence_captured"), do: "Evidence captured"
  def event_label("review_saved"), do: "Assessment saved"
  def event_label("disappeared"), do: "No longer observed in local inventory"
  def event_label(value), do: text(value)
end
