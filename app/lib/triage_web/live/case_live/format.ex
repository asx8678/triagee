defmodule TriageWeb.CaseLive.Format do
  @moduledoc """
  Pure view-model formatting for the review case detail.

  A frozen snapshot payload is normalized into plain display maps, and every
  stored value degrades to a visible placeholder instead of crashing a
  template. Shared by `TriageWeb.CaseLive.Show` and its section components, so
  how a stored value is displayed has one definition rather than two.
  """

  # The frozen snapshot payload is normalized into a plain display map so the
  # template never touches a live Inventory preload. Missing or malformed
  # payload values degrade to visible placeholders, never a crash.
  def empty_evidence do
    %{
      schema_version: nil,
      source: nil,
      scope_owner: nil,
      scope_environment: nil,
      finding: %{},
      image: %{},
      placements: [],
      events: [],
      coverage: nil
    }
  end

  def evidence_view(payload) when is_map(payload) do
    %{
      schema_version: pget(payload, "schema_version"),
      source: pget(payload, "source"),
      scope_owner: pget(pget(payload, "scope"), "owner"),
      scope_environment: pget(pget(payload, "scope"), "environment"),
      finding: %{
        cve: pget2(payload, "finding", "cve"),
        package_name: pget2(payload, "finding", "package_name"),
        package_version: pget2(payload, "finding", "package_version"),
        severity: pget2(payload, "finding", "severity"),
        fix: pget2(payload, "finding", "fix"),
        url: pget2(payload, "finding", "url"),
        description: pget2(payload, "finding", "description"),
        suppressed: pget2(payload, "finding", "suppressed"),
        first_seen: pget2(payload, "finding", "first_seen"),
        last_seen: pget2(payload, "finding", "last_seen"),
        resolved_at: pget2(payload, "finding", "resolved_at"),
        reopen_count: pget2(payload, "finding", "reopen_count")
      },
      image: %{
        digest: pget2(payload, "image", "digest"),
        repository: pget2(payload, "image", "repository"),
        tag: pget2(payload, "image", "tag"),
        description: pget2(payload, "image", "description")
      },
      placements: placement_views(pget(payload, "placements")),
      events: event_views(pget(payload, "events")),
      coverage: coverage_text(pget(payload, "coverage"))
    }
  end

  def evidence_view(_other), do: empty_evidence()

  def placement_views(list) when is_list(list) do
    for placement <- list do
      %{
        id: pget(placement, "id"),
        owner: pget(placement, "owner"),
        namespace: pget(placement, "namespace"),
        environment: pget(placement, "environment"),
        active: pget(placement, "active"),
        first_seen: pget(placement, "first_seen"),
        last_seen: pget(placement, "last_seen")
      }
    end
  end

  def placement_views(_other), do: []

  def event_views(list) when is_list(list) do
    for event <- list do
      %{
        id: pget(event, "id"),
        event: pget(event, "event"),
        occurred_at: pget(event, "occurred_at"),
        note: pget(event, "note")
      }
    end
  end

  def event_views(_other), do: []

  def pget(map, key) when is_map(map) and is_binary(key), do: Map.get(map, key)
  def pget(_other, _key), do: nil

  def pget2(map, key, sub), do: map |> pget(key) |> pget(sub)

  # The coverage payload entry is structured (kind + warning); only the plain
  # warning text is displayed, never a raw dump of the map.
  def coverage_text(%{"warning" => warning}) when is_binary(warning), do: warning
  def coverage_text(value), do: text(value)

  def snapshot_views(data) do
    current_id = data.case.current_snapshot_id

    for snapshot <- data.snapshots do
      %{
        id: snapshot.id,
        version: snapshot.version,
        payload_hash: snapshot.payload_hash,
        captured_at: snapshot.captured_at,
        evidence: evidence_view(snapshot.payload),
        is_current: snapshot.id == current_id
      }
    end
  end

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

  def detail_pairs(detail) when is_map(detail) do
    detail
    |> Map.keys()
    |> Enum.sort()
    |> Enum.map(fn key -> %{key: safe_text(key), value: safe_text(Map.get(detail, key))} end)
  end

  def detail_pairs(_other), do: []

  def safe_text(value) when is_binary(value), do: value
  def safe_text(value), do: inspect(value)

  def time_key(%DateTime{} = dt), do: DateTime.to_unix(dt)

  def time_key(%NaiveDateTime{} = ndt),
    do: :calendar.datetime_to_gregorian_seconds(NaiveDateTime.to_erl(ndt))

  def time_key(_other), do: 0

  def text(value) when value in [nil, ""], do: "Not reported"
  def text(value) when is_binary(value), do: value
  def text(value), do: inspect(value)

  def active_label(true), do: "active"
  def active_label(false), do: "retired"
  def active_label(_other), do: "Not captured"

  # The three manual assessment choices live here with the label lookup that
  # reads them, so the form's option lists and the display of a stored key
  # cannot describe different sets of choices.
  @applicability_options [
    {"Affected", "affected"},
    {"Not affected with evidence", "not_affected_with_evidence"},
    {"Unknown", "unknown"}
  ]

  @priority_options [
    {"Expedited review", "expedited_review"},
    {"Normal review", "normal_review"},
    {"Insufficient context", "insufficient_context"}
  ]

  @next_action_options [
    {"Investigation", "investigation"},
    {"Dependency update", "dependency_update"},
    {"Base image update", "base_image_update"},
    {"Rebuild and redeploy", "rebuild_deploy"},
    {"Mitigation review", "mitigation_review"},
    {"Exception proposal", "exception_proposal"}
  ]

  @doc "The applicability choices, as `{label, stored key}`."
  def applicability_options, do: @applicability_options

  @doc "The priority choices, as `{label, stored key}`."
  def priority_options, do: @priority_options

  @doc "The next-action choices, as `{label, stored key}`."
  def next_action_options, do: @next_action_options

  def label(value) do
    options = @applicability_options ++ @priority_options ++ @next_action_options

    case Enum.find(options, fn {_label, key} -> key == value end) do
      {label, _} -> label
      nil -> event_label(value)
    end
  end

  def event_label("case_opened"), do: "Case opened"
  def event_label("evidence_captured"), do: "Evidence captured"
  def event_label("review_saved"), do: "Assessment saved"
  def event_label("disappeared"), do: "No longer observed in local inventory"
  def event_label(value), do: text(value)

  def image_reference(image) do
    case {image[:repository], image[:tag]} do
      {repository, tag}
      when is_binary(repository) and repository != "" and is_binary(tag) and tag != "" ->
        repository <> ":" <> tag

      {repository, _} when is_binary(repository) and repository != "" ->
        repository

      _ ->
        image[:digest]
    end
  end

  def source_label("synthetic_local_inventory"), do: "Synthetic local inventory"
  def source_label(value), do: text(value)

  def evidence_label(:current), do: "Local evidence match"
  def evidence_label(:changed), do: "Local evidence changed"
  def evidence_label(:source_out_of_scope), do: "Source out of saved scope"
  def evidence_label(_), do: "Source unavailable"
end
