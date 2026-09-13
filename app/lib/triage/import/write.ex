defmodule Triage.Import.Write do
  @moduledoc """
  The write path for the snapshot import: every entry point runs inside the
  caller transaction with the import advisory lock held first, and the stale
  observation rule is applied before anything is written.

  These functions are public only so the public import API can call them; they
  are internal to the import pipeline and are not part of the application API.
  """

  use Triage.Import.Contract

  alias Triage.Import.Parse
  alias Triage.Import.Reconcile
  alias Triage.Inventory.Finding
  alias Triage.Inventory.FindingEvent
  alias Triage.Inventory.Image
  alias Triage.Inventory.ImagePlacement
  alias Triage.Repo

  ## Write path (always inside the caller's transaction, lock held first)

  def do_write!(snapshot) do
    lock_import!()

    digests = Enum.map(snapshot.images, & &1.digest)
    existing_images = Reconcile.load_images(digests)
    image_ids = Reconcile.existing_image_ids(existing_images)
    existing_placements = Reconcile.load_placements(image_ids)
    existing_findings = Reconcile.load_findings(image_ids)
    existing_events = Reconcile.load_events(existing_findings)

    case regression_errors(snapshot, existing_images, existing_placements, existing_findings) do
      [] ->
        :ok

      errors ->
        Repo.rollback({:import_rejected, errors})
    end

    warnings = resolution_warnings(snapshot, existing_images, existing_findings)

    rows =
      Enum.map(snapshot.images, fn image ->
        {record, action} = write_image(image, Map.get(existing_images, image.digest))

        placements = write_placements(image.placements, record.id, existing_placements)
        findings = write_findings(image.findings, record.id, existing_findings, existing_events)

        %{
          digest: image.digest,
          image_id: record.id,
          action: action,
          placements: placements,
          findings: findings
        }
      end)

    %{
      summary: Reconcile.summarize(rows),
      images: rows,
      warnings: warnings
    }
  end

  def lock_import! do
    Repo.query!("SELECT pg_advisory_xact_lock($1)", [@import_lock_key])
  end

  def write_image(image, nil) do
    record =
      %Image{}
      |> Image.changeset(%{
        digest: image.digest,
        repository: image.repository,
        tag: image.tag,
        description: image.description
      })
      |> Repo.insert!()

    {record, :create}
  end

  def write_image(image, existing) do
    if Reconcile.image_action(existing, image) == :unchanged do
      {existing, :unchanged}
    else
      record =
        existing
        |> Image.changeset(%{
          repository: image.repository,
          tag: image.tag,
          description: image.description
        })
        |> Repo.update!()

      {record, :update}
    end
  end

  def write_placements(placements, image_id, existing_map) do
    Enum.map(placements, fn placement ->
      key = {image_id, placement.namespace, placement.owner, placement.environment}

      action =
        case Map.get(existing_map, key) do
          nil ->
            %ImagePlacement{}
            |> ImagePlacement.changeset(%{
              image_id: image_id,
              namespace: placement.namespace,
              owner: placement.owner,
              environment: placement.environment,
              active: if(is_nil(placement.active), do: true, else: placement.active),
              first_seen: placement.first_seen,
              last_seen: placement.last_seen
            })
            |> Repo.insert!()

            :create

          existing ->
            if Reconcile.placement_changed?(existing, placement) do
              existing |> ImagePlacement.changeset(placement_attrs(placement)) |> Repo.update!()
              :update
            else
              :unchanged
            end
        end

      %{key: {placement.namespace, placement.owner, placement.environment}, action: action}
    end)
  end

  def placement_attrs(placement) do
    attrs = %{first_seen: placement.first_seen, last_seen: placement.last_seen}

    if is_nil(placement.active), do: attrs, else: Map.put(attrs, :active, placement.active)
  end

  def write_findings(findings, image_id, existing_map, existing_events) do
    Enum.map(findings, fn finding ->
      key = {image_id, finding.cve, finding.package_name, finding.package_version}
      existing = Map.get(existing_map, key)

      {record, action} =
        case existing do
          nil ->
            record =
              %Finding{}
              |> Finding.changeset(%{
                image_id: image_id,
                cve: finding.cve,
                package_name: finding.package_name,
                package_version: finding.package_version,
                severity: finding.severity,
                fix: finding.fix,
                url: finding.url,
                description: finding.description,
                suppressed: if(is_nil(finding.suppressed), do: false, else: finding.suppressed),
                first_seen: finding.first_seen,
                last_seen: finding.last_seen,
                resolved_at: finding.resolved_at
              })
              |> Repo.insert!()

            {record, :create}

          existing ->
            if Reconcile.finding_changed?(existing, finding) do
              {existing |> Finding.changeset(finding_attrs(finding)) |> Repo.update!(), :update}
            else
              {existing, :unchanged}
            end
        end

      known = Map.get(existing_events, record.id, MapSet.new())
      events = write_events(finding.events, record.id, known)

      %{
        key: {finding.cve, finding.package_name, finding.package_version},
        action: action,
        events: events
      }
    end)
  end

  # Update attrs never include `reopen_count` (local counter) and only include
  # `suppressed`/`resolved_at` when the snapshot actually states them.
  def finding_attrs(finding) do
    attrs = %{
      severity: finding.severity,
      fix: finding.fix,
      url: finding.url,
      description: finding.description,
      first_seen: finding.first_seen,
      last_seen: finding.last_seen
    }

    attrs =
      if is_nil(finding.suppressed),
        do: attrs,
        else: Map.put(attrs, :suppressed, finding.suppressed)

    if is_nil(finding.resolved_at),
      do: attrs,
      else: Map.put(attrs, :resolved_at, finding.resolved_at)
  end

  def write_events(events, finding_id, known) do
    Enum.map(events, fn event ->
      action =
        if MapSet.member?(known, {event.event, event.occurred_at}) do
          :existing
        else
          %FindingEvent{}
          |> FindingEvent.changeset(%{
            finding_id: finding_id,
            event: event.event,
            occurred_at: event.occurred_at,
            note: event.note
          })
          |> Repo.insert!()

          :create
        end

      %{key: {event.event, event.occurred_at}, action: action}
    end)
  end

  ## Stale-observation rejection (before any write)

  def regression_errors(snapshot, images, placements, findings) do
    snapshot.images
    |> Enum.with_index()
    |> Enum.reduce([], fn {image, image_index}, errors ->
      case Map.get(images, image.digest) do
        nil ->
          errors

        existing_image ->
          errors
          |> placement_regressions(image, image_index, existing_image, placements)
          |> finding_regressions(image, image_index, existing_image, findings)
      end
    end)
    |> Enum.reverse()
  end

  def placement_regressions(errors, image, image_index, existing_image, placements) do
    image.placements
    |> Enum.with_index()
    |> Enum.reduce(errors, fn {placement, index}, errors ->
      key = {existing_image.id, placement.namespace, placement.owner, placement.environment}
      path = "$.images[#{image_index}].placements[#{index}]"

      case Map.get(placements, key) do
        nil -> errors
        existing -> observation_regressions(errors, existing, placement, path)
      end
    end)
  end

  def finding_regressions(errors, image, image_index, existing_image, findings) do
    image.findings
    |> Enum.with_index()
    |> Enum.reduce(errors, fn {finding, index}, errors ->
      key = {existing_image.id, finding.cve, finding.package_name, finding.package_version}
      path = "$.images[#{image_index}].findings[#{index}]"

      case Map.get(findings, key) do
        nil -> errors
        existing -> observation_regressions(errors, existing, finding, path)
      end
    end)
  end

  def observation_regressions(errors, existing, incoming, path) do
    errors
    |> maybe_regression(
      earlier?(incoming.last_seen, existing.last_seen),
      "#{path}.last_seen",
      "incoming last_seen #{fmt(incoming.last_seen)} is older than the recorded local value " <>
        "#{fmt(existing.last_seen)}; refusing to regress a recorded observation time"
    )
    |> maybe_regression(
      later?(incoming.first_seen, existing.first_seen),
      "#{path}.first_seen",
      "incoming first_seen #{fmt(incoming.first_seen)} is later than the recorded local value " <>
        "#{fmt(existing.first_seen)}; refusing to regress a recorded observation time"
    )
  end

  def maybe_regression(errors, true, path, message), do: errors ++ [Parse.problem(path, message)]
  def maybe_regression(errors, false, _path, _message), do: errors

  def earlier?(nil, _existing), do: false
  def earlier?(_incoming, nil), do: false

  def earlier?(incoming, existing),
    do: DateTime.compare(truncate(incoming), truncate(existing)) == :lt

  def later?(nil, _existing), do: false
  def later?(_incoming, nil), do: false

  def later?(incoming, existing),
    do: DateTime.compare(truncate(incoming), truncate(existing)) == :gt

  def truncate(%DateTime{} = datetime), do: DateTime.truncate(datetime, :second)
  def truncate(other), do: other

  def fmt(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)
  def fmt(other), do: inspect(other)

  # Shared by `dry_run/1` and `write!/1` so the preview and the commit disclose
  # the same preservation decision, with the real indexed snapshot path.
  def resolution_warnings(snapshot, images, findings) do
    snapshot.images
    |> Enum.with_index()
    |> Enum.reduce([], fn {image, image_index}, warnings ->
      case Map.get(images, image.digest) do
        nil ->
          warnings

        existing_image ->
          image.findings
          |> Enum.with_index()
          |> Enum.reduce(warnings, fn {finding, finding_index}, warnings ->
            key = {existing_image.id, finding.cve, finding.package_name, finding.package_version}

            case Map.get(findings, key) do
              %Finding{resolved_at: resolved} when not is_nil(resolved) ->
                if is_nil(finding.resolved_at) do
                  [
                    Parse.problem(
                      "$.images[#{image_index}].findings[#{finding_index}].resolved_at",
                      "snapshot does not state resolution; the recorded local resolved_at is preserved"
                    )
                    | warnings
                  ]
                else
                  warnings
                end

              _ ->
                warnings
            end
          end)
      end
    end)
    |> Enum.reverse()
  end
end
