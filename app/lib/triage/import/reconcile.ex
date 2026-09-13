defmodule Triage.Import.Reconcile do
  @moduledoc """
  Read-only reconciliation for the snapshot import: loading the current local
  rows for the snapshot images and comparing each record, so a reimport is
  idempotent by construction. Never writes.

  These functions are public only so the other import stages can call them; they
  are internal to the import pipeline and are not part of the application API.
  """

  import Ecto.Query

  alias Triage.Inventory.Finding
  alias Triage.Inventory.FindingEvent
  alias Triage.Inventory.Image
  alias Triage.Inventory.ImagePlacement
  alias Triage.Repo

  ## Reconciliation

  def load_images([]), do: %{}

  def load_images(digests) do
    from(i in Image, where: i.digest in ^digests, select: i)
    |> Repo.all()
    |> Map.new(&{&1.digest, &1})
  end

  def existing_image_ids(images), do: images |> Map.values() |> Enum.map(& &1.id)

  def load_placements([]), do: %{}

  def load_placements(image_ids) do
    from(p in ImagePlacement, where: p.image_id in ^image_ids)
    |> Repo.all()
    |> Map.new(&{{&1.image_id, &1.namespace, &1.owner, &1.environment}, &1})
  end

  def load_findings([]), do: %{}

  def load_findings(image_ids) do
    from(f in Finding, where: f.image_id in ^image_ids)
    |> Repo.all()
    |> Map.new(&{{&1.image_id, &1.cve, &1.package_name, &1.package_version}, &1})
  end

  def load_events(findings) do
    finding_ids = findings |> Map.values() |> Enum.map(& &1.id)

    if finding_ids == [] do
      %{}
    else
      from(e in FindingEvent, where: e.finding_id in ^finding_ids)
      |> Repo.all()
      |> Enum.group_by(& &1.finding_id, &{&1.event, DateTime.truncate(&1.occurred_at, :second)})
      |> Map.new(fn {finding_id, keys} -> {finding_id, MapSet.new(keys)} end)
    end
  end

  def reconcile(snapshot, images, placements, findings, events) do
    Enum.map(snapshot.images, fn image ->
      existing_image = Map.get(images, image.digest)
      image_action = image_action(existing_image, image)
      image_id = existing_image && existing_image.id

      placements = reconcile_placements(image.placements, image_id, placements)
      findings = reconcile_findings(image.findings, image_id, findings, events)

      %{
        digest: image.digest,
        action: image_action,
        image_id: image_id,
        placements: placements,
        findings: findings
      }
    end)
  end

  def image_action(nil, _image), do: :create

  def image_action(existing, image) do
    if existing.repository == image.repository and existing.tag == image.tag and
         existing.description == image.description do
      :unchanged
    else
      :update
    end
  end

  def reconcile_placements(placements, image_id, existing_map) do
    Enum.map(placements, fn placement ->
      key = {image_id, placement.namespace, placement.owner, placement.environment}

      action =
        case Map.get(existing_map, key) do
          nil -> :create
          existing -> if placement_changed?(existing, placement), do: :update, else: :unchanged
        end

      %{key: {placement.namespace, placement.owner, placement.environment}, action: action}
    end)
  end

  def placement_changed?(existing, placement) do
    (not is_nil(placement.active) and existing.active != placement.active) or
      DateTime.truncate(existing.first_seen, :second) != placement.first_seen or
      DateTime.truncate(existing.last_seen, :second) != placement.last_seen
  end

  def reconcile_findings(findings, image_id, existing_map, events) do
    Enum.map(findings, fn finding ->
      key = {image_id, finding.cve, finding.package_name, finding.package_version}
      existing = Map.get(existing_map, key)

      action =
        case existing do
          nil -> :create
          existing -> if finding_changed?(existing, finding), do: :update, else: :unchanged
        end

      event_rows = reconcile_events(finding.events, existing && existing.id, events)

      %{
        key: {finding.cve, finding.package_name, finding.package_version},
        action: action,
        events: event_rows
      }
    end)
  end

  def finding_changed?(existing, finding) do
    existing.severity != finding.severity or
      existing.fix != finding.fix or
      existing.url != finding.url or
      existing.description != finding.description or
      (not is_nil(finding.suppressed) and existing.suppressed != finding.suppressed) or
      DateTime.truncate(existing.first_seen, :second) != finding.first_seen or
      DateTime.truncate(existing.last_seen, :second) != finding.last_seen or
      resolution_changed?(existing, finding)
  end

  # A snapshot may set or move `resolved_at`, never clear it: an export that
  # omits resolution is not evidence that anything was remediated.
  def resolution_changed?(existing, finding) do
    not is_nil(finding.resolved_at) and
      truncate_optional(existing.resolved_at) != finding.resolved_at
  end

  def truncate_optional(nil), do: nil
  def truncate_optional(datetime), do: DateTime.truncate(datetime, :second)

  def reconcile_events(events, finding_id, existing_events) do
    known =
      if finding_id, do: Map.get(existing_events, finding_id, MapSet.new()), else: MapSet.new()

    Enum.map(events, fn event ->
      action =
        if MapSet.member?(known, {event.event, event.occurred_at}), do: :existing, else: :create

      %{key: {event.event, event.occurred_at}, action: action}
    end)
  end

  def summarize(rows) do
    all_placements = Enum.flat_map(rows, & &1.placements)
    all_findings = Enum.flat_map(rows, & &1.findings)
    all_events = Enum.flat_map(all_findings, & &1.events)

    %{
      images: counts(Enum.map(rows, & &1.action)),
      placements: counts(Enum.map(all_placements, & &1.action)),
      findings: counts(Enum.map(all_findings, & &1.action)),
      events: counts(Enum.map(all_events, & &1.action))
    }
  end

  def counts(actions) do
    Enum.reduce(actions, %{create: 0, update: 0, unchanged: 0, existing: 0}, fn action, acc ->
      Map.update!(acc, action, &(&1 + 1))
    end)
  end
end
