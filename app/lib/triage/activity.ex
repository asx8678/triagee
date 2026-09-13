defmodule Triage.Activity do
  @moduledoc """
  Read-only local "What's New" feed over the append-only `finding_events` log.

  This is a local lifecycle activity feed, not public news, not an authorization
  boundary and not a completeness or remediation claim:

    * Exactly one row per recorded event - never one row per placement or per CVE
      - ordered by event `id DESC` ("Newest recorded first (record ID order)").
      `occurred_at` is the "Recorded observation time" and never changes the
      ordering, so backdated or exactly-tied observation times cannot reorder rows.
    * Fixed page size 25 with a 26th sentinel row; only the first 25 rows are
      enriched. `next_before_id` is the last displayed id and is present only
      when a further page exists.
    * All three event kinds are included, and findings that are currently
      resolved or suppressed are not excluded: disappearance is an observation,
      not verified remediation.
    * The finding and image fields are the CURRENT local metadata joined to an
      existing event, not frozen historical facts. They can change after the
      event was recorded and must not be read as what was true then.
    * Optional `:owner`/`:environment` filters combine with AND on the SAME
      recorded placement. Scope means "events for findings whose image has a
      recorded placement matching the filters", not historical attribution to
      that team or environment when the event occurred. Inactive placements are
      included in the match. Unscoped feeds include events with no placements at
      all; scoped feeds exclude them.
    * `detail_available?` is true when the feed is unscoped or the finding's
      image has a matching *active* placement, mirroring the current finding
      detail gate. Suppression is not mitigation and absence is not remediation.

  Invalid input is rejected before any query; nothing here writes.
  """

  import Ecto.Query

  alias Triage.Repo
  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}

  @page_size 25
  @fetch_limit @page_size + 1

  @opt_keys [:owner, :environment, :before_id]
  @max_id 9_223_372_036_854_775_807
  @scope_max 120
  @unsafe_scope ~r/[\x00-\x1F\x7F]/

  @doc """
  Lists recorded lifecycle events newest recorded id first.

  `opts` must be a keyword list accepting only `:owner`, `:environment` and
  `:before_id`. Any other request shape - non-lists, non-keyword lists, maps,
  structs and lists with unknown or duplicate keys - returns
  `{:error, :invalid_request}` before any query. Scope values are `nil` or a
  plain valid-UTF-8 binary with no raw NUL/C0/DEL, at most 120 characters after
  trimming; blank (the All choice) becomes `nil`, and any other value is
  `{:error, :invalid_scope}` before any query. `:before_id` is `nil` or a
  positive integer within the signed 64-bit range, otherwise
  `{:error, :invalid_cursor}`.

  Returns `{:ok, %{rows: rows, has_more?: boolean, next_before_id: integer | nil}}`.
  """
  def list_events(opts \\ []) do
    with {:ok, request} <- validate_request(opts) do
      load_events(request)
    end
  end

  @doc """
  Sorted distinct nonblank owner and environment values from every recorded
  placement, active and inactive. At most two SELECTs; no per-row work.
  """
  def event_filter_options do
    %{
      owners: distinct_scopes(ImagePlacement, :owner),
      environments: distinct_scopes(ImagePlacement, :environment)
    }
  end

  ## Request validation - completes before any query

  defp validate_request(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      validate_keys(opts)
    else
      {:error, :invalid_request}
    end
  end

  defp validate_request(_opts), do: {:error, :invalid_request}

  defp validate_keys(opts) do
    keys = Keyword.keys(opts)

    cond do
      not Enum.all?(keys, &(&1 in @opt_keys)) -> {:error, :invalid_request}
      length(keys) != length(Enum.uniq(keys)) -> {:error, :invalid_request}
      true -> validate_values(opts)
    end
  end

  defp validate_values(opts) do
    with {:ok, before_id} <- validate_before_id(Keyword.get(opts, :before_id)),
         {:ok, owner} <- validate_scope(Keyword.get(opts, :owner)),
         {:ok, environment} <- validate_scope(Keyword.get(opts, :environment)) do
      {:ok, %{owner: owner, environment: environment, before_id: before_id}}
    end
  end

  defp validate_scope(nil), do: {:ok, nil}

  defp validate_scope(value) when not is_binary(value), do: {:error, :invalid_scope}

  defp validate_scope(value) do
    cond do
      not String.valid?(value) ->
        {:error, :invalid_scope}

      Regex.match?(@unsafe_scope, value) ->
        {:error, :invalid_scope}

      true ->
        case String.trim(value) do
          "" ->
            {:ok, nil}

          trimmed ->
            if String.length(trimmed) > @scope_max,
              do: {:error, :invalid_scope},
              else: {:ok, trimmed}
        end
    end
  end

  defp validate_before_id(nil), do: {:ok, nil}

  defp validate_before_id(before_id) do
    if is_integer(before_id) and not is_boolean(before_id) and before_id > 0 and
         before_id <= @max_id do
      {:ok, before_id}
    else
      {:error, :invalid_cursor}
    end
  end

  ## Load

  defp load_events(%{owner: owner, environment: environment, before_id: before_id}) do
    scoped? = not is_nil(owner) or not is_nil(environment)

    candidates = page_events(owner, environment, before_id)

    {displayed, has_more?} =
      if length(candidates) > @page_size do
        {Enum.take(candidates, @page_size), true}
      else
        {candidates, false}
      end

    placements = page_placements(displayed, owner, environment)
    rows = build_rows(displayed, placements, scoped?)

    next_before_id =
      if has_more? do
        {event, _finding, _image} = List.last(displayed)
        event.id
      else
        nil
      end

    {:ok, %{rows: rows, has_more?: has_more?, next_before_id: next_before_id}}
  end

  # One SELECT: event joined to its current finding and image, filtered by
  # `EXISTS (subquery)` on the finding's image so a finding with many matching
  # placements is still one row (dedupe before LIMIT, never a multiplicative
  # join).
  defp page_events(owner, environment, before_id) do
    from(e in FindingEvent,
      join: f in Finding,
      as: :finding,
      on: f.id == e.finding_id,
      join: i in Image,
      on: i.id == f.image_id,
      order_by: [desc: e.id],
      limit: ^@fetch_limit,
      select: {e, f, i}
    )
    |> maybe_before(before_id)
    |> apply_page_scope(owner, environment)
    |> Repo.all()
  end

  defp maybe_before(query, nil), do: query

  defp maybe_before(query, before_id), do: where(query, [e], e.id < ^before_id)

  defp apply_page_scope(query, nil, nil), do: query

  defp apply_page_scope(query, owner, nil) do
    where(
      query,
      exists(
        from(p in ImagePlacement,
          where: p.image_id == parent_as(:finding).image_id and p.owner == ^owner,
          select: 1
        )
      )
    )
  end

  defp apply_page_scope(query, nil, environment) do
    where(
      query,
      exists(
        from(p in ImagePlacement,
          where: p.image_id == parent_as(:finding).image_id and p.environment == ^environment,
          select: 1
        )
      )
    )
  end

  defp apply_page_scope(query, owner, environment) do
    where(
      query,
      exists(
        from(p in ImagePlacement,
          where:
            p.image_id == parent_as(:finding).image_id and p.owner == ^owner and
              p.environment == ^environment,
          select: 1
        )
      )
    )
  end

  # Second SELECT: the displayed images' placements. Unscoped keeps every
  # recorded placement; scoped keeps only placements matching the filters,
  # including inactive ones. Deterministic order.
  defp page_placements([], _owner, _environment), do: %{}

  defp page_placements(displayed, owner, environment) do
    image_ids =
      displayed
      |> Enum.map(fn {_event, finding, _image} -> finding.image_id end)
      |> Enum.uniq()

    from(p in ImagePlacement, where: p.image_id in ^image_ids)
    |> apply_placement_scope(owner, environment)
    |> order_by([p], asc: p.owner, asc: p.namespace, asc: p.environment, asc: p.id)
    |> Repo.all()
    |> Enum.group_by(& &1.image_id)
  end

  defp apply_placement_scope(query, nil, nil), do: query
  defp apply_placement_scope(query, owner, nil), do: where(query, [p], p.owner == ^owner)

  defp apply_placement_scope(query, nil, environment),
    do: where(query, [p], p.environment == ^environment)

  defp apply_placement_scope(query, owner, environment),
    do: where(query, [p], p.owner == ^owner and p.environment == ^environment)

  defp build_rows(displayed, placements_by_image, scoped?) do
    Enum.map(displayed, fn {event, finding, image} ->
      placements =
        placements_by_image
        |> Map.get(finding.image_id, [])
        |> Enum.map(fn placement ->
          %{
            owner: placement.owner,
            environment: placement.environment,
            namespace: placement.namespace,
            active: placement.active
          }
        end)

      %{
        id: event.id,
        finding_id: event.finding_id,
        event: event.event,
        occurred_at: event.occurred_at,
        note: event.note,
        finding: %{
          cve: finding.cve,
          package_name: finding.package_name,
          package_version: finding.package_version,
          severity: finding.severity,
          suppressed: finding.suppressed,
          resolved_at: finding.resolved_at
        },
        image: %{digest: image.digest, repository: image.repository, tag: image.tag},
        placements: placements,
        detail_available?: not scoped? or Enum.any?(placements, & &1.active)
      }
    end)
  end

  ## Filter options

  defp distinct_scopes(queryable, field) do
    from(p in queryable, distinct: true, select: field(p, ^field), order_by: field(p, ^field))
    |> Repo.all()
    |> Enum.reject(fn value -> is_nil(value) or String.trim(value) == "" end)
  end
end
