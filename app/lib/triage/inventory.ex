defmodule Triage.Inventory do
  @moduledoc """
  Read model over scanner observations: images, placements, findings and lifecycle events.

  Identity follows the legacy collector's safeguards:

    * images are keyed on the immutable content digest, never on rotating API ids;
    * a finding is one (image, advisory, package, version) occurrence — a CVE is
      not a case, and the UI groups by CVE only for navigation;
    * placements carry team (owner) and environment/cluster scope; an unknown
      namespace stays explicitly unknown;
    * suppression and disappearance are observations, never proof of remediation.

  PR 1 is an offline demo: this context is populated by deterministic synthetic
  fixtures (`Triage.Seeds`) and never contacts a security API.
  """

  import Ecto.Query
  alias Triage.Repo

  @severity_order ~w(CRITICAL HIGH MEDIUM LOW)
  @unsafe_text ~r/[\x00-\x1F\x7F]/

  defmodule Image do
    use Ecto.Schema
    import Ecto.Changeset

    schema "images" do
      field :digest, :string
      field :repository, :string
      field :tag, :string
      field :description, :string

      timestamps(type: :utc_datetime)
    end

    def changeset(image, attrs) do
      image
      |> cast(attrs, [:digest, :repository, :tag, :description])
      |> validate_required([:digest])
      |> unique_constraint(:digest)
    end
  end

  defmodule CveDetail do
    @moduledoc false
    @type t :: %__MODULE__{cve: String.t(), occurrences: list(), placements: list()}
    defstruct [:cve, occurrences: [], placements: []]
  end

  defmodule ImagePlacement do
    use Ecto.Schema
    import Ecto.Changeset

    schema "image_placements" do
      belongs_to :image, Image
      field :namespace, :string
      field :owner, :string
      field :environment, :string
      field :active, :boolean, default: true
      field :first_seen, :utc_datetime
      field :last_seen, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    def changeset(placement, attrs) do
      placement
      |> cast(attrs, [
        :image_id,
        :namespace,
        :owner,
        :environment,
        :active,
        :first_seen,
        :last_seen
      ])
      |> validate_required([:image_id, :namespace, :owner, :environment, :first_seen, :last_seen])
      |> unique_constraint([:image_id, :namespace, :owner, :environment])
    end
  end

  defmodule Finding do
    use Ecto.Schema
    import Ecto.Changeset

    schema "findings" do
      belongs_to :image, Image
      field :cve, :string
      field :package_name, :string
      field :package_version, :string
      field :severity, :string
      field :fix, :string
      field :url, :string
      field :description, :string
      field :suppressed, :boolean, default: false
      field :first_seen, :utc_datetime
      field :last_seen, :utc_datetime
      field :resolved_at, :utc_datetime
      field :reopen_count, :integer, default: 0

      timestamps(type: :utc_datetime)
    end

    def changeset(finding, attrs) do
      finding
      |> cast(attrs, [
        :image_id,
        :cve,
        :package_name,
        :package_version,
        :severity,
        :fix,
        :url,
        :description,
        :suppressed,
        :first_seen,
        :last_seen,
        :resolved_at,
        :reopen_count
      ])
      |> validate_required([
        :image_id,
        :cve,
        :package_name,
        :package_version,
        :first_seen,
        :last_seen
      ])
      |> foreign_key_constraint(:image_id)
      |> unique_constraint([:image_id, :cve, :package_name, :package_version])
    end
  end

  defmodule FindingEvent do
    use Ecto.Schema
    import Ecto.Changeset

    # No association back to Finding on purpose: lifecycle events are queried
    # explicitly so the event log stays append-only and independent.
    schema "finding_events" do
      field :finding_id, :integer
      field :event, :string
      field :occurred_at, :utc_datetime
      field :note, :string

      timestamps(type: :utc_datetime)
    end

    def changeset(event, attrs) do
      event
      |> cast(attrs, [:finding_id, :event, :occurred_at, :note])
      |> validate_required([:finding_id, :event, :occurred_at])
      |> validate_inclusion(:event, ~w(appeared resolved reopened))
    end
  end

  # Highest scanner severity present in a group, as a rank. Shared by the
  # selected column and the default ordering so the two cannot drift.
  @severity_rank_sql "max(case ? when 'CRITICAL' then 4 when 'HIGH' then 3 when 'MEDIUM' then 2 when 'LOW' then 1 else 0 end)"

  @group_sorts ~w(severity newest occurrences cve)
  @default_group_sort "severity"
  @max_group_limit 200

  @doc "Result orders accepted by `list_groups/1` through its `:sort` option."
  def group_sorts, do: @group_sorts

  @doc """
  The order applied when `:sort` is omitted. Exposed so the filter contract and
  the list view share one definition instead of restating it.
  """
  def default_group_sort, do: @default_group_sort

  @doc """
  Groups open findings by advisory for the list view.

  Options:

    * `:owner` — restrict to placements of one team. An owner with no placements
      yields an empty list; the filter is never treated as authorization.
    * `:environment` — restrict to placements of one environment/cluster.
    * `:include_suppressed` — include scanner-suppressed findings (labelled in UI;
      suppression is not mitigation evidence).
    * `:search` — group-level match on advisory id or any affected package, so a
      package search cannot hide other affected packages of the same advisory.
    * `:sort` — one of `Triage.Inventory.group_sorts/0`; unknown values raise
      instead of silently returning a different order. Every order is a strict
      total order (advisory id is the final tie-break), so paging cannot
      duplicate or skip a group.
    * `:limit` — page size: a non-negative integer of at most 200, so one
      request cannot pull the whole inventory.
    * `:offset` — non-negative integer of groups to skip. Unbounded, because a
      later page of a large inventory is a legitimate cursor position. Use
      `count_groups/1` for the unpaged total, and clamp the requested page
      against it before computing the offset.

  Findings that disappeared from an eligible collection (`resolved_at`) are never
  listed here; absence is not verified remediation.
  """
  def list_groups(opts \\ []) do
    page_limit = normalize_paging(opts[:limit], :limit)
    page_offset = normalize_paging(opts[:offset], :offset)
    sort = normalize_group_sort(opts[:sort])

    opts
    |> filtered_findings()
    |> group_by([f], f.cve)
    |> select([f, p], %{
      cve: f.cve,
      first_occurrence_id: fragment("min(?)", f.id),
      severity_rank: fragment(@severity_rank_sql, f.severity),
      occurrences: fragment("count(distinct ?)", f.id),
      images: fragment("count(distinct ?)", f.image_id),
      teams: fragment("count(distinct ?)", p.owner),
      team_names:
        fragment("array_agg(distinct ?) filter (where ? is not null)", p.owner, p.owner),
      packages: fragment("count(distinct ?)", f.package_name),
      fixable:
        fragment("count(distinct case when coalesce(?, '') <> '' then ? end)", f.fix, f.id),
      suppressed_occurrences:
        fragment("count(distinct case when ? then ? end)", f.suppressed, f.id),
      reopened: max(f.reopen_count),
      first_seen: min(f.first_seen),
      last_seen: max(f.last_seen)
    })
    |> apply_group_order(sort)
    |> apply_group_paging(page_limit, page_offset)
    |> Repo.all()
  end

  @doc """
  Unpaged count of the advisory groups matching the same predicates as
  `list_groups/1`. A page total computed from this can never disagree with the
  rows, because both come from `filtered_findings/1`.
  """
  def count_groups(opts \\ []) do
    # Counted over the same grouped rows, because the group search predicate is
    # an aggregate (bool_or) that is only valid in a grouped query.
    groups =
      opts
      |> filtered_findings()
      |> group_by([f], f.cve)
      |> select([f, _p], %{cve: f.cve})

    Repo.aggregate(from(g in subquery(groups)), :count)
  end

  # Single definition of the group predicates shared by `list_groups/1` and
  # `count_groups/1`.
  defp filtered_findings(opts) do
    owner = normalize(opts[:owner])
    environment = normalize(opts[:environment])
    include_suppressed? = Keyword.get(opts, :include_suppressed, false)
    search = normalize(opts[:search])
    severity = normalize_severity_filter(opts[:severity])

    from(f in Finding)
    |> where([f], is_nil(f.resolved_at))
    |> apply_severity_filter(severity)
    |> apply_suppression_filter(include_suppressed?)
    |> join(:inner, [f], p in ImagePlacement, on: p.image_id == f.image_id and p.active == true)
    |> apply_scope(owner, environment)
    |> apply_group_search(search)
  end

  # Every ordering below is a strict total order: the advisory id is always the
  # final tie-break, so no two groups can compare equal and paging can neither
  # duplicate nor skip a group.
  defp apply_group_order(query, "severity") do
    query
    |> order_by([f],
      desc: fragment(@severity_rank_sql, f.severity),
      desc: fragment("count(distinct ?)", f.image_id),
      asc: f.cve
    )
  end

  defp apply_group_order(query, "newest") do
    order_by(query, [f], desc: fragment("min(?)", f.first_seen), asc: f.cve)
  end

  defp apply_group_order(query, "occurrences") do
    order_by(query, [f], desc: fragment("count(distinct ?)", f.id), asc: f.cve)
  end

  defp apply_group_order(query, "cve"), do: order_by(query, [f], asc: f.cve)

  defp apply_group_paging(query, nil, nil), do: query

  defp apply_group_paging(query, page_limit, page_offset) do
    query
    |> maybe_limit(page_limit)
    |> maybe_offset(page_offset)
  end

  defp maybe_limit(query, nil), do: query
  defp maybe_limit(query, page_limit), do: limit(query, ^page_limit)

  defp maybe_offset(query, nil), do: query
  defp maybe_offset(query, page_offset), do: offset(query, ^page_offset)

  defp normalize_group_sort(nil), do: @default_group_sort

  defp normalize_group_sort(sort) when is_binary(sort) do
    case sort |> String.trim() |> String.downcase() do
      "" -> @default_group_sort
      normalized -> if normalized in @group_sorts, do: normalized, else: raise_invalid_sort(sort)
    end
  end

  defp normalize_group_sort(other), do: raise_invalid_sort(other)

  defp raise_invalid_sort(sort) do
    raise ArgumentError,
          "unsupported group sort #{inspect(sort)}; expected one of #{inspect(@group_sorts)}"
  end

  defp normalize_paging(nil, _name), do: nil

  # A page size is bounded so one request cannot pull the whole inventory.
  defp normalize_paging(value, :limit)
       when is_integer(value) and value >= 0 and value <= @max_group_limit,
       do: value

  # An offset is not bounded by the page-size limit: a later page of a large
  # inventory is a legitimate cursor position, and callers reach it only after
  # clamping the page number against the real total.
  defp normalize_paging(value, :offset) when is_integer(value) and value >= 0, do: value

  defp normalize_paging(value, :limit) do
    raise ArgumentError,
          "invalid limit #{inspect(value)}; expected an integer from 0 to #{@max_group_limit}"
  end

  defp normalize_paging(value, :offset) do
    raise ArgumentError,
          "invalid offset #{inspect(value)}; expected a non-negative integer"
  end

  def teams do
    Repo.all(from p in ImagePlacement, distinct: true, select: p.owner, order_by: p.owner)
  end

  def environments do
    Repo.all(
      from p in ImagePlacement, distinct: true, select: p.environment, order_by: p.environment
    )
  end

  @doc "Header counts for the inventory banner."
  def summary_counts do
    open =
      Repo.one(
        from f in Finding, where: is_nil(f.resolved_at) and f.suppressed == false, select: count()
      )

    suppressed =
      Repo.one(
        from f in Finding, where: is_nil(f.resolved_at) and f.suppressed == true, select: count()
      )

    %{open: open || 0, suppressed: suppressed || 0}
  end

  @doc """
  Distinct-CVE counts by severity, consistent with `list_groups/1`:
  only active-placement, non-suppressed, unresolved findings.
  """
  def cve_summary_counts do
    rows =
      from(f in Finding)
      |> where([f], is_nil(f.resolved_at) and f.suppressed == false)
      |> join(:inner, [f], p in ImagePlacement, on: p.image_id == f.image_id and p.active == true)
      |> group_by([f], f.severity)
      |> select([f], %{severity: f.severity, distinct_cves: fragment("count(distinct ?)", f.cve)})
      |> Repo.all()

    counts = Map.new(rows, fn row -> {row.severity, row.distinct_cves} end)
    total = Enum.reduce(counts, 0, fn {_sev, n}, acc -> acc + n end)

    %{
      total: total,
      critical: Map.get(counts, "CRITICAL", 0),
      high: Map.get(counts, "HIGH", 0),
      medium: Map.get(counts, "MEDIUM", 0),
      low: Map.get(counts, "LOW", 0)
    }
  end

  @doc """
  Newest CVE groups by first local observation (`first_seen`), newest first,
  stable tie-break on CVE id. Same predicates as `list_groups/1`, implemented
  as its `sort: "newest"` order so the overview rail and the findings list
  cannot drift apart. This is *local observation newness*, never CVE
  publication time.
  """
  def newest_cve_groups(limit \\ 10), do: list_groups(sort: "newest", limit: limit)

  @doc """
  CVE-centric aggregate: every current occurrence of the advisory across all
  teams, images and placements, with exposure evidence joined per placement.

  `cve` is validated as a non-blank safe string (no control characters) before
  any query. Scoped visibility (`:owner`, `:environment`) restricts which
  occurrences and placements are shown, mirroring `fetch_finding/2` — display
  scoping, not authorization.
  """
  def fetch_cve(cve, opts \\ [])

  def fetch_cve(cve, _opts)
      when not is_binary(cve),
      do: {:error, :invalid_cve}

  def fetch_cve(cve, opts) do
    trimmed = String.trim(cve)

    if trimmed == "" or not String.valid?(cve) or Regex.match?(@unsafe_text, cve) do
      {:error, :invalid_cve}
    else
      load_cve_aggregate(trimmed, opts)
    end
  end

  defp load_cve_aggregate(cve, opts) do
    owner = normalize(opts[:owner])
    environment = normalize(opts[:environment])

    case Repo.all(occurrence_base(cve, owner, environment)) do
      [] ->
        {:error, :not_found}

      occurrences ->
        image_ids = occurrences |> Enum.map(& &1.image_id) |> Enum.uniq()

        placements =
          from(p in ImagePlacement,
            where: p.image_id in ^image_ids,
            order_by: [asc: p.owner, asc: p.namespace, asc: p.environment, asc: p.id]
          )
          |> Repo.all()

        exposure_map =
          Triage.Exposure.current_by_placement(Enum.map(placements, & &1.id))

        %Triage.Inventory.CveDetail{
          cve: cve,
          occurrences: occurrences,
          placements:
            Enum.map(placements, fn p ->
              %{
                placement: p,
                exposure: Map.get(exposure_map, p.id, "unknown")
              }
            end)
        }
        |> then(&{:ok, &1})
    end
  end

  defp occurrence_base(cve, owner, environment) do
    query =
      from(f in Finding,
        where: f.cve == ^cve and is_nil(f.resolved_at),
        order_by: [asc: f.package_name, asc: f.id],
        preload: :image
      )

    # Scope via images holding an active matching placement (semijoin
    # semantics). The scope stays a subquery: materializing every active scoped
    # image id in memory would make this query's cost scale with the tenant
    # rather than with the rows it returns.
    if is_nil(owner) and is_nil(environment) do
      query
    else
      where(query, [f], f.image_id in subquery(active_placement_image_ids(owner, environment)))
    end
  end

  # findings.id is a bigint (bigserial) primary key: the guard keeps malformed,
  # zero, negative and out-of-range ids off the database and failing predictably.
  # int8 max is exactly 2^63 - 1 (9_223_372_036_854_775_807). This module is the
  # single runtime source of truth for the upper bound: the web layer only
  # parses ids into positive integers and delegates validation here.
  @max_finding_id Integer.pow(2, 63) - 1

  @doc """
  Loads one finding occurrence with its image, placements and lifecycle events.

  `id` must be a positive integer within the bigint primary-key range;
  anything else returns `:error` instead of raising.

  Options:

    * `:owner` — restrict displayed placements and related occurrences to one
      team. A finding with no active placement in the selected scope returns
      `{:error, :out_of_scope}` so a scoped view can never silently bind a
      decision to another team's context. This is display scoping, not
      authorization.
    * `:environment` — restrict to one environment/cluster.

  Without scope options all placements and occurrences are returned. Scope
  values must be strings (or nil); see `normalize/1`.
  """
  def fetch_finding(id, opts \\ [])

  def fetch_finding(id, _opts) when not is_integer(id) or id <= 0 or id > @max_finding_id,
    do: :error

  def fetch_finding(id, opts) do
    owner = normalize(opts[:owner])
    environment = normalize(opts[:environment])
    scoped? = not is_nil(owner) or not is_nil(environment)

    case Repo.get(Finding, id) do
      nil ->
        :error

      finding ->
        finding = Repo.preload(finding, :image)

        all_placements =
          Repo.all(
            from p in ImagePlacement,
              where: p.image_id == ^finding.image_id,
              order_by: [p.owner, p.namespace, p.environment]
          )

        scoped_placements = filter_placements(all_placements, owner, environment)

        if scoped? and not Enum.any?(scoped_placements, & &1.active) do
          {:error, :out_of_scope}
        else
          events =
            Repo.all(
              from e in FindingEvent,
                where: e.finding_id == ^finding.id,
                order_by: [asc: e.occurred_at, asc: e.id]
            )

          other_occurrences =
            from(f in Finding,
              where: f.cve == ^finding.cve and f.id != ^finding.id and is_nil(f.resolved_at),
              order_by: f.package_name,
              preload: :image
            )
            |> scope_by_active_placement(owner, environment)
            |> Repo.all()

          {:ok,
           %{
             finding: finding,
             placements: if(scoped?, do: scoped_placements, else: all_placements),
             events: events,
             other_occurrences: other_occurrences
           }}
        end
    end
  end

  defp filter_placements(placements, nil, nil), do: placements

  defp filter_placements(placements, owner, nil),
    do: Enum.filter(placements, &(&1.owner == owner))

  defp filter_placements(placements, nil, environment),
    do: Enum.filter(placements, &(&1.environment == environment))

  defp filter_placements(placements, owner, environment),
    do: Enum.filter(placements, &(&1.owner == owner and &1.environment == environment))

  # Active scoped images as a query, never as a materialized id list: the
  # semijoin keeps the work in PostgreSQL and lets the planner drive it from the
  # placement's image id index instead of returning one row per active placement
  # to Elixir.
  defp active_placement_image_ids(owner, environment) do
    from(p in ImagePlacement, where: p.active == true, select: p.image_id)
    |> apply_placement_scope(owner, environment)
  end

  defp apply_placement_scope(query, nil, nil), do: query

  defp apply_placement_scope(query, owner, nil), do: where(query, [p], p.owner == ^owner)

  defp apply_placement_scope(query, nil, environment),
    do: where(query, [p], p.environment == ^environment)

  defp apply_placement_scope(query, owner, environment),
    do: where(query, [p], p.owner == ^owner and p.environment == ^environment)

  defp scope_by_active_placement(query, nil, nil), do: query

  defp scope_by_active_placement(query, owner, environment) do
    where(query, [f], f.image_id in subquery(active_placement_image_ids(owner, environment)))
  end

  @doc "Inserts or updates an image keyed by immutable digest."
  def upsert_image(attrs, _now) do
    %Image{}
    |> Image.changeset(Map.merge(attrs, %{digest: String.downcase(attrs.digest)}))
    |> Repo.insert(
      on_conflict: {:replace, [:repository, :tag, :description, :updated_at]},
      conflict_target: :digest,
      returning: true
    )
    |> case do
      {:ok, image} -> {:ok, image}
      other -> other
    end
  end

  @doc "Inserts or refreshes one team/environment placement of an image."
  def upsert_placement(image, attrs, now) do
    %ImagePlacement{}
    |> ImagePlacement.changeset(
      Map.merge(attrs, %{image_id: image.id, first_seen: now, last_seen: now})
    )
    |> Repo.insert(
      on_conflict: [set: [last_seen: now, active: true, updated_at: now]],
      conflict_target: [:image_id, :namespace, :owner, :environment]
    )
  end

  @doc """
  Inserts or refreshes one finding occurrence.

  With `reopen: true` (the live-collection default), a finding that was previously
  marked resolved gets `resolved_at` cleared, its `reopen_count` incremented and a
  `reopened` event. Seeds pass `reopen: false` and manage lifecycle explicitly so
  replaying the fixtures never invents history.
  """
  def upsert_finding(image, attrs, now, opts \\ []) do
    reopen? = Keyword.get(opts, :reopen, true)

    Repo.transaction(fn ->
      existing =
        Repo.one(
          from f in Finding,
            where:
              f.image_id == ^image.id and f.cve == ^attrs.cve and
                f.package_name == ^attrs.package_name and
                f.package_version == ^attrs.package_version
        )

      event_name =
        cond do
          is_nil(existing) -> "appeared"
          reopen? and not is_nil(existing.resolved_at) -> "reopened"
          true -> nil
        end

      changeset_attrs = Map.merge(attrs, %{image_id: image.id, last_seen: now})

      finding =
        case existing do
          nil ->
            %Finding{}
            |> Finding.changeset(
              Map.merge(changeset_attrs, %{first_seen: now, resolved_at: nil, reopen_count: 0})
            )
            |> Repo.insert!()

          existing when reopen? and not is_nil(existing.resolved_at) ->
            existing
            |> Finding.changeset(
              Map.merge(changeset_attrs, %{
                resolved_at: nil,
                reopen_count: existing.reopen_count + 1
              })
            )
            |> Repo.update!()

          existing ->
            existing |> Finding.changeset(changeset_attrs) |> Repo.update!()
        end

      if event_name do
        insert_event!(finding.id, event_name, now)
      end

      finding
    end)
  end

  @doc "Appends one lifecycle event. Events are never updated or deleted."
  def record_event(finding_id, event_name, occurred_at, note \\ nil) do
    insert_event!(finding_id, event_name, occurred_at, note)
    :ok
  end

  @doc "Used by seeds to pin recorded history: first detection, disappearance and reopens."
  def set_lifecycle(finding_id, attrs) do
    finding = Repo.get!(Finding, finding_id)
    changes = Map.take(Enum.into(attrs, %{}), [:first_seen, :resolved_at, :reopen_count])

    finding
    |> Finding.changeset(changes)
    |> Repo.update!()

    :ok
  end

  defp insert_event!(finding_id, event_name, occurred_at, note \\ nil) do
    %FindingEvent{}
    |> FindingEvent.changeset(%{
      finding_id: finding_id,
      event: event_name,
      occurred_at: occurred_at,
      note: note
    })
    |> Repo.insert!()
  end

  defp apply_suppression_filter(query, true), do: query
  defp apply_suppression_filter(query, false), do: where(query, [f], f.suppressed == false)

  defp apply_severity_filter(query, nil), do: query

  defp apply_severity_filter(query, severity),
    do: where(query, [f], f.severity == ^severity)

  # A severity filter is nil (All) or one of the known scanner severities;
  # anything else is rejected before the database as invalid, not widened.
  defp normalize_severity_filter(nil), do: nil

  defp normalize_severity_filter(value) when is_binary(value) do
    normalized = value |> String.trim() |> String.upcase()

    cond do
      not String.valid?(value) ->
        raise ArgumentError, "severity filter must be valid UTF-8"

      normalized == "" ->
        nil

      normalized in @severity_order ->
        normalized

      true ->
        raise ArgumentError, "unknown severity filter: " <> inspect(value)
    end
  end

  defp normalize_severity_filter(value),
    do: raise(ArgumentError, "severity filter must be a string or nil, got: " <> inspect(value))

  defp apply_scope(query, nil, nil), do: query
  defp apply_scope(query, owner, nil), do: where(query, [f, p], p.owner == ^owner)

  defp apply_scope(query, nil, environment),
    do: where(query, [f, p], p.environment == ^environment)

  defp apply_scope(query, owner, environment),
    do: where(query, [f, p], p.owner == ^owner and p.environment == ^environment)

  defp apply_group_search(query, nil), do: query

  defp apply_group_search(query, search) do
    pattern = "%" <> String.downcase(search) <> "%"

    having(
      query,
      [f],
      fragment(
        "bool_or(lower(?) like ?) or lower(?) like ?",
        f.package_name,
        ^pattern,
        f.cve,
        ^pattern
      )
    )
  end

  # Scope values are accepted only as plain, trimmed strings. Blank stays the
  # intentional unscoped/All choice. Everything else is rejected *before* the
  # database: `to_string` coercion could turn `[:alpha]`-style values into a
  # real team name, truncation could alias a longer name, and PostgreSQL
  # rejects NUL bytes with character_not_in_repertoire. Overlength strings are
  # passed through untruncated so they can only ever match an identical name.
  # Validation runs on the RAW binary *before* trimming: a control character or
  # invalid UTF-8 must be rejected even when trimming would remove it.
  defp normalize(nil), do: nil

  defp normalize(value) when is_binary(value) do
    cond do
      not String.valid?(value) ->
        raise ArgumentError,
              "scope values must be valid UTF-8, got: " <> inspect(value)

      Regex.match?(@unsafe_text, value) ->
        raise ArgumentError,
              "scope values must not contain NUL or control characters, got: " <> inspect(value)

      true ->
        case String.trim(value) do
          "" -> nil
          trimmed -> trimmed
        end
    end
  end

  defp normalize(value) do
    raise ArgumentError, "scope values must be strings or nil, got: " <> inspect(value)
  end

  @severity_labels %{4 => "CRITICAL", 3 => "HIGH", 2 => "MEDIUM", 1 => "LOW", 0 => "UNKNOWN"}

  @doc "Maps an internal severity rank to its label for display."
  def severity_label(rank), do: Map.get(@severity_labels, rank, "UNKNOWN")

  def severity_order, do: @severity_order
end
