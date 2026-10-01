defmodule Triage.Import.Lifecycle do
  @moduledoc """
  Opt-in lifecycle for a snapshot the operator declares complete
  (`mix triage.import --complete`).

  A plain import never reads anything into absence. A complete snapshot is a
  stronger statement: it is the full current state, as of its `generated_at`,
  of every team and environment pair it mentions and of every image it lists.
  Only under that statement does absence mean something:

    * a deployment of a mentioned team and environment that the snapshot does
      not list is retired (`active: false`), which is what happens when a
      workload moves to a new image;
    * an open finding on a listed image that the snapshot does not list is
      recorded as no longer observed at `generated_at`, with a `resolved` event;
    * a finding recorded as no longer observed that the snapshot lists again,
      seen after that time, is reopened with a `reopened` event.

  Findings belong to the image, not to a team: a listed image must carry its
  full finding list even when several teams run it. Deployments are retired
  only for the team and environment pairs the snapshot itself mentions.

  "No longer observed" stays an observation: it is not verified remediation.
  A snapshot whose `generated_at` is older than a recorded observation it would
  close is rejected, so an out-of-date file cannot close newer findings.

  `plan/1` only reads and is what the dry run shows; `apply!/2` runs inside the
  import transaction, after the ordinary write and under its advisory lock.
  """

  import Ecto.Query

  alias Triage.Import.Parse
  alias Triage.Import.Reconcile
  alias Triage.Inventory.Finding
  alias Triage.Inventory.FindingEvent
  alias Triage.Inventory.Image
  alias Triage.Inventory.ImagePlacement
  alias Triage.Repo

  @resolved_note "Absent from a complete snapshot"
  @reopened_note "Listed again in a complete snapshot"
  @examples 10

  @doc "The dry-run report with the lifecycle changes a complete import would make."
  def preview(snapshot, report) do
    with {:ok, plan} <- plan(snapshot), do: {:ok, merge(report, plan)}
  end

  @doc "Applies the lifecycle changes inside the caller's import transaction."
  def apply!(snapshot, report) do
    case plan(snapshot) do
      {:ok, plan} ->
        write!(plan)
        merge(report, plan)

      {:error, errors} ->
        Repo.rollback({:import_rejected, errors})
    end
  end

  @doc "Read-only: what a complete snapshot retires, closes and reopens."
  def plan(%{generated_at: nil}) do
    {:error,
     [
       Parse.problem(
         "$.generated_at",
         "a complete snapshot must state generated_at, the time it describes"
       )
     ]}
  end

  def plan(snapshot) do
    at = snapshot.generated_at
    images = Reconcile.load_images(Enum.map(snapshot.images, & &1.digest))
    retire = placements_to_retire(snapshot)
    {resolve, reopen} = finding_changes(snapshot, images)

    case stale_errors(retire, resolve, at) do
      [] -> {:ok, %{at: at, retire: retire, resolve: resolve, reopen: reopen}}
      errors -> {:error, errors}
    end
  end

  # Active deployments of every team and environment pair the snapshot mentions
  # that the snapshot itself does not list.
  defp placements_to_retire(snapshot) do
    listed =
      for image <- snapshot.images, placement <- image.placements, into: MapSet.new() do
        {image.digest, placement.namespace, placement.owner, placement.environment}
      end

    pairs = MapSet.new(listed, fn {_digest, _namespace, owner, env} -> {owner, env} end)

    if MapSet.size(pairs) == 0 do
      []
    else
      owners = pairs |> Enum.map(&elem(&1, 0)) |> Enum.uniq()
      environments = pairs |> Enum.map(&elem(&1, 1)) |> Enum.uniq()

      from(p in ImagePlacement,
        join: i in Image,
        on: i.id == p.image_id,
        where: p.active and p.owner in ^owners and p.environment in ^environments,
        order_by: [asc: p.id],
        select: {p, i}
      )
      |> Repo.all()
      |> Enum.filter(fn {placement, image} ->
        MapSet.member?(pairs, {placement.owner, placement.environment}) and
          not MapSet.member?(
            listed,
            {image.digest, placement.namespace, placement.owner, placement.environment}
          )
      end)
      |> Enum.map(fn {placement, image} -> %{placement: placement, image: image} end)
    end
  end

  defp finding_changes(snapshot, images) do
    image_ids = Reconcile.existing_image_ids(images)

    recorded =
      if image_ids == [] do
        %{}
      else
        from(f in Finding, where: f.image_id in ^image_ids, order_by: [asc: f.id])
        |> Repo.all()
        |> Enum.group_by(& &1.image_id)
      end

    snapshot.images
    |> Enum.with_index()
    |> Enum.reduce({[], []}, fn {image, image_index}, {resolve, reopen} ->
      record = Map.get(images, image.digest)
      findings = if record, do: Map.get(recorded, record.id, []), else: []
      {absent, back} = image_changes(image, image_index, record, findings)
      {resolve ++ absent, reopen ++ back}
    end)
  end

  # For one listed image: its recorded open findings the snapshot omits, and
  # its recorded closed findings the snapshot lists again, seen later.
  defp image_changes(_image, _image_index, nil, _findings), do: {[], []}

  defp image_changes(image, image_index, record, findings) do
    listed =
      image.findings
      |> Enum.with_index()
      |> Map.new(fn {finding, index} -> {identity(finding), {finding, index}} end)

    absent =
      for finding <- findings,
          is_nil(finding.resolved_at),
          not Map.has_key?(listed, identity(finding)),
          do: %{finding: finding, image: record}

    back =
      for finding <- findings,
          not is_nil(finding.resolved_at),
          {incoming, index} <- List.wrap(Map.get(listed, identity(finding))),
          is_nil(incoming.resolved_at),
          DateTime.compare(incoming.last_seen, finding.resolved_at) == :gt do
        %{
          finding: finding,
          image: record,
          at: incoming.last_seen,
          path: "$.images[#{image_index}].findings[#{index}]"
        }
      end

    {absent, back}
  end

  defp identity(finding), do: {finding.cve, finding.package_name, finding.package_version}

  # A snapshot older than an observation it would close proves nothing about it.
  defp stale_errors(retire, resolve, at) do
    placements =
      for %{placement: placement, image: image} <- retire, later?(placement.last_seen, at) do
        Parse.problem(
          "$.generated_at",
          "the snapshot is older than a recorded observation it would retire: " <>
            "#{placement.owner}/#{placement.environment}/#{placement.namespace} on " <>
            "#{image.digest} was last seen #{DateTime.to_iso8601(placement.last_seen)}"
        )
      end

    findings =
      for %{finding: finding, image: image} <- resolve, later?(finding.last_seen, at) do
        Parse.problem(
          "$.generated_at",
          "the snapshot is older than a recorded observation it would close: " <>
            "#{describe(finding)} on #{image.digest} was last seen " <>
            DateTime.to_iso8601(finding.last_seen)
        )
      end

    Enum.take(placements ++ findings, @examples)
  end

  defp later?(nil, _at), do: false
  defp later?(seen, at), do: DateTime.compare(DateTime.truncate(seen, :second), at) == :gt

  defp write!(plan) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    placement_ids = Enum.map(plan.retire, & &1.placement.id)

    if placement_ids != [] do
      Repo.update_all(from(p in ImagePlacement, where: p.id in ^placement_ids),
        set: [active: false, updated_at: now]
      )
    end

    resolved_ids = Enum.map(plan.resolve, & &1.finding.id)

    if resolved_ids != [] do
      Repo.update_all(from(f in Finding, where: f.id in ^resolved_ids),
        set: [resolved_at: plan.at, updated_at: now]
      )

      Repo.insert_all(
        FindingEvent,
        Enum.map(resolved_ids, &event_row(&1, "resolved", plan.at, @resolved_note, now))
      )
    end

    for %{finding: finding, at: at} <- plan.reopen do
      Repo.update_all(from(f in Finding, where: f.id == ^finding.id),
        set: [resolved_at: nil, updated_at: now],
        inc: [reopen_count: 1]
      )

      Repo.insert_all(FindingEvent, [event_row(finding.id, "reopened", at, @reopened_note, now)])
    end

    :ok
  end

  defp event_row(finding_id, event, occurred_at, note, now) do
    %{
      finding_id: finding_id,
      event: event,
      occurred_at: occurred_at,
      note: note,
      inserted_at: now,
      updated_at: now
    }
  end

  # A reopened finding no longer keeps its recorded resolution, so the plain
  # import's "resolved_at is preserved" warning for it would be wrong.
  defp merge(report, plan) do
    reopened = MapSet.new(plan.reopen, &(&1.path <> ".resolved_at"))

    report
    |> Map.update!(:warnings, fn warnings ->
      Enum.reject(warnings, &MapSet.member?(reopened, &1.path))
    end)
    |> Map.put(:lifecycle, %{
      as_of: plan.at,
      retired_placements: length(plan.retire),
      resolved_findings: length(plan.resolve),
      reopened_findings: length(plan.reopen),
      examples: %{
        retired:
          plan.retire
          |> Enum.take(@examples)
          |> Enum.map(fn %{placement: placement, image: image} ->
            "#{placement.owner}/#{placement.environment}/#{placement.namespace} on #{label(image)}"
          end),
        resolved:
          plan.resolve
          |> Enum.take(@examples)
          |> Enum.map(fn %{finding: finding, image: image} ->
            "#{describe(finding)} on #{label(image)}"
          end),
        reopened:
          plan.reopen
          |> Enum.take(@examples)
          |> Enum.map(fn %{finding: finding, image: image} ->
            "#{describe(finding)} on #{label(image)}"
          end)
      }
    })
  end

  defp describe(finding), do: "#{finding.cve} #{finding.package_name} #{finding.package_version}"

  defp label(%{repository: repository, tag: tag}) when is_binary(repository) and is_binary(tag),
    do: "#{repository}:#{tag}"

  defp label(%{repository: repository}) when is_binary(repository), do: repository
  defp label(%{digest: digest}), do: digest
end
