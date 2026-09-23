defmodule Triage.Intel do
  @moduledoc """
  Cached public vulnerability intelligence.

  Separation of concerns (per the approved plan):

    * Internal inventory (teams/images/occurrences) is local and untouched —
      internet adapters NEVER write findings, placements, cases or reviews.
    * Public intelligence is cached in its own tables with source, publication
      and fetch timestamps; provenance is required on every record.
    * Adapters run ONLY through the explicit manual CLI (`mix triage.intel`) or
      a future explicitly-enabled scheduled task — there is no request-time
      download, no fetch button, and the default config disables all sources.
    * A failed refresh preserves the last good cache and records a receipt.

  News and KEV items are public notices, never a statement about the local
  estate: "not found here" is not "not affected".
  """

  import Ecto.Query
  alias Triage.Repo

  defmodule Advisory do
    @moduledoc false
    use Ecto.Schema
    import Ecto.Changeset

    schema "intel_advisories" do
      field :source, :string
      field :external_id, :string
      field :summary, :string
      field :published_at, :utc_datetime
      field :fetched_at, :utc_datetime
      # KEV actionability, carried from the feed. Nil for NVD rows and for rows
      # cached before these columns existed — displayed as "not captured".
      field :required_action, :string
      field :due_date, :utc_datetime
      field :known_ransomware, :boolean
      # The immutable validated generation this row belongs to. NULL means a
      # pre-generation (legacy) row: readable while it is the only cache for its
      # source, never retroactively certified as a complete catalogue.
      belongs_to :generation, Triage.Intel.Generation

      timestamps(type: :utc_datetime)
    end

    def changeset(advisory, attrs) do
      advisory
      |> cast(attrs, [
        :source,
        :external_id,
        :summary,
        :published_at,
        :fetched_at,
        :required_action,
        :due_date,
        :known_ransomware,
        :generation_id
      ])
      |> validate_required([:source, :external_id, :fetched_at])
      |> unique_constraint([:source, :external_id], name: :intel_advisories_legacy_identity_index)
      |> unique_constraint([:source, :generation_id, :external_id],
        name: :intel_advisories_generation_identity_index
      )
    end
  end

  defmodule NewsItem do
    @moduledoc false
    use Ecto.Schema
    import Ecto.Changeset

    schema "news_items" do
      field :source, :string
      field :item_id, :string
      field :title, :string
      field :summary, :string
      field :link, :string
      field :published_at, :utc_datetime
      field :fetched_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    def changeset(item, attrs) do
      item
      |> cast(attrs, [:source, :item_id, :title, :summary, :link, :published_at, :fetched_at])
      |> validate_required([:source, :item_id, :title, :fetched_at])
      |> unique_constraint([:source, :item_id])
    end
  end

  defmodule RefreshReceipt do
    @moduledoc false
    use Ecto.Schema
    import Ecto.Changeset

    schema "intel_refresh_receipts" do
      field :source, :string
      field :attempted_at, :utc_datetime
      field :succeeded, :boolean, default: false
      field :item_count, :integer
      field :message, :string

      timestamps(type: :utc_datetime)
    end

    def changeset(receipt, attrs) do
      receipt
      |> cast(attrs, [:source, :attempted_at, :succeeded, :item_count, :message])
      |> validate_required([:source, :attempted_at, :succeeded])
    end
  end

  alias __MODULE__.{Advisory, CurrentGeneration, Generation, NewsItem, RefreshReceipt}

  @news_limit_default 10
  @valid_schemes ~w(https)

  ## ---- Cached reads (NO network here — pure database reads) ----

  @doc "Latest news items, most recently fetched/published first, bounded."
  def list_cached_news(limit \\ @news_limit_default) when is_integer(limit) and limit > 0 do
    from(n in NewsItem,
      order_by: [desc: n.published_at, desc: n.fetched_at, desc: n.id],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc "Advisories for a CVE external id, all sources, newest fetch first."
  def cached_advisories(external_id) when is_binary(external_id) do
    from(a in Advisory, where: a.external_id == ^external_id, order_by: [desc: a.fetched_at])
    |> current_rows()
    |> Repo.all()
  end

  def cached_advisories(_other), do: []

  @doc """
  Cached KEV advisories for one CVE.

  `mix triage.intel --kev` stores KEV rows with `source: "kev"` and the bare CVE as
  `external_id`, so the source name is never part of the external id. Reading by a
  `"kev:" <> cve` external id (or storing one) silently returns nothing.
  """
  def cached_kev(cve) when is_binary(cve) do
    from(a in Advisory,
      where: a.source == "kev" and a.external_id == ^cve,
      order_by: [desc: a.fetched_at, desc: a.id]
    )
    |> current_rows()
    |> Repo.all()
  end

  def cached_kev(_other), do: []

  @doc """
  Cached KEV rows for a set of advisory ids, keyed by id, for list views.

  One batched read: calling `cached_kev/1` once per rendered row would be one query per
  row. The predicate is deliberately the same as `cached_kev/1` — `source == "kev"` and an
  exact `external_id` match — so the batched and the single read can never disagree about
  whether an advisory is in the cache. Ids are deduplicated, and blank or non-binary ones
  are dropped, so a row with no captured advisory id contributes no lookup.

  A missing key means the cache holds no row for that id. That is never a statement that
  the advisory is not exploited, and callers must render it as no marker at all.
  """
  @spec kev_index([String.t()] | term()) :: %{optional(String.t()) => map()}
  def kev_index(cves) when is_list(cves) do
    ids =
      cves
      |> Enum.filter(&is_binary/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()

    if ids == [] do
      %{}
    else
      from(a in Advisory,
        where: a.source == "kev" and a.external_id in ^ids,
        order_by: [desc: a.fetched_at, desc: a.id]
      )
      |> current_rows()
      |> Repo.all()
      |> Enum.reduce(%{}, fn row, acc -> Map.put_new(acc, row.external_id, row) end)
    end
  end

  def kev_index(_other), do: %{}

  @doc """
  The newest cached KEV row for a single advisory id, or nil.

  The detail pages read one advisory at a time, so they use this instead of the batched
  `kev_index/1`: `cached_kev/1` already orders newest first, which makes this that read
  without the list. Nil means the cache holds no row for the id — never that the advisory
  is not exploited — and a blank or non-binary id performs no query at all.
  """
  @spec kev_row(term()) :: map() | nil
  def kev_row(cve) when is_binary(cve) and cve != "", do: cve |> cached_kev() |> List.first()
  def kev_row(_other), do: nil

  @doc """
  Cached NVD advisories for one CVE.

  NVD refreshes are per CVE, so the source key carries the CVE
  (`"nvd:CVE-…"`, uppercased exactly as the CLI writes it) while `external_id`
  stays the identifier the payload reported. The source is the authoritative key
  here; it is never folded into the external id.
  """
  def cached_nvd(cve) when is_binary(cve) do
    source = nvd_source(cve)

    from(a in Advisory, where: a.source == ^source, order_by: [desc: a.fetched_at, desc: a.id])
    |> current_rows()
    |> Repo.all()
  end

  def cached_nvd(_other), do: []

  @doc """
  Canonical source key for a per-CVE NVD refresh: `"nvd:CVE-…"`.

  The CLI writes rows under this key and `cached_nvd/1` reads it, so both derive it
  here. Spelling it out separately in the success and failure paths is how a failed
  refresh ends up recorded under a differently cased source than the row it protects.
  """
  def nvd_source(cve) when is_binary(cve), do: "nvd:" <> String.upcase(String.trim(cve))

  @doc "Current advisory rows for one source, independent of a per-CVE match or refresh receipt."
  @spec cached_advisory_count(String.t()) :: non_neg_integer()
  def cached_advisory_count(source) when is_binary(source) do
    from(a in Advisory, where: a.source == ^source)
    |> current_rows()
    |> Repo.aggregate(:count)
  end

  ## ---- Generations (validated, immutable intelligence snapshots) ----

  # Current readers see exactly one generation per source. Before a source has a
  # committed generation, pre-migration rows (`generation_id IS NULL`) are the
  # cache, exactly as they were before this table existed: readable, but never
  # retroactively certified as a complete catalogue. Once a generation is
  # current, legacy rows stay in history and are never mixed into a certified
  # read.
  defp current_rows(query) do
    from(a in query,
      where:
        fragment(
          "? IS NULL AND NOT EXISTS (SELECT 1 FROM intel_current_generations c WHERE c.source = ?)",
          a.generation_id,
          a.source
        ) or
          fragment(
            "? = (SELECT c.generation_id FROM intel_current_generations c WHERE c.source = ?)",
            a.generation_id,
            a.source
          )
    )
  end

  @doc "The validated generation a source currently serves, or nil (legacy cache)."
  @spec current_generation(String.t()) :: struct() | nil
  def current_generation(source) when is_binary(source) do
    from(c in CurrentGeneration,
      join: g in Generation,
      on: g.id == c.generation_id,
      where: c.source == ^source,
      select: g
    )
    |> Repo.one()
  end

  @doc "Stored generations for a source, newest first — cited history, never rewritten."
  @spec generation_history(String.t(), pos_integer()) :: [struct()]
  def generation_history(source, limit \\ 20)
      when is_binary(source) and is_integer(limit) and limit > 0 do
    from(g in Generation, where: g.source == ^source, order_by: [desc: g.id], limit: ^limit)
    |> Repo.all()
  end

  @doc "The rows of one exact stored generation, readable after the source moves on."
  @spec generation_rows(String.t(), integer()) :: [struct()]
  def generation_rows(source, generation_id)
      when is_binary(source) and is_integer(generation_id) do
    from(a in Advisory,
      where: a.source == ^source and a.generation_id == ^generation_id,
      order_by: [asc: a.external_id]
    )
    |> Repo.all()
  end

  @doc "Latest refresh receipt per source (for stale-status display)."
  def latest_receipts do
    from(r in RefreshReceipt,
      order_by: [asc: r.source, desc: r.attempted_at, desc: r.id],
      distinct: r.source
    )
    |> Repo.all()
  end

  @doc """
  Read-only KEV source status, independent of matches in the displayed inventory.

  Reads the whole-source cache count and latest receipt once per page load, never
  per advisory. A failed receipt does not invalidate or remove cached matches.
  No receipt means no recorded refresh, even if rows were populated separately.
  """
  @spec kev_status() :: %{
          source: String.t(),
          rows: non_neg_integer(),
          receipt: map() | nil,
          generation: map() | nil
        }
  def kev_status do
    %{
      source: "kev",
      rows: cached_advisory_count("kev"),
      receipt: Enum.find(latest_receipts(), &(&1.source == "kev")),
      generation: generation_summary(current_generation("kev"))
    }
  end

  defp generation_summary(nil), do: nil

  defp generation_summary(generation) do
    %{
      id: generation.id,
      complete: generation.complete,
      row_count: generation.row_count,
      declared_count: generation.declared_count,
      catalog_version: generation.catalog_version,
      started_at: generation.started_at,
      fetched_at: generation.fetched_at
    }
  end

  @doc "Insert a refresh receipt. Receipts are append-only."
  def record_receipt(source, succeeded, item_count \\ nil, message \\ nil) do
    %RefreshReceipt{}
    |> RefreshReceipt.changeset(%{
      source: source,
      attempted_at: DateTime.utc_now(),
      succeeded: succeeded,
      item_count: item_count,
      message: message
    })
    |> Repo.insert()
  end

  ## ---- Cache writes (adapters call these via the CLI path only) ----

  @doc """
  Stores a validated replacement for one source as a new immutable generation.

  One transaction writes the generation, its rows, the current pointer and —
  unless `receipt: false` — the success receipt, so a refresh can never leave a
  new cache without its receipt or move the pointer without its rows.

  `complete` must only be true when the caller's validation proved the source's
  own completeness contract. The pointer moves only when this attempt is
  strictly newer than the current generation, comparing `started_at` (when the
  refresh began) rather than when this transaction happened to run: an older
  attempt that completes last is stored as history and cannot displace a newer
  valid generation.
  """
  @spec commit_generation(String.t(), [map()], keyword()) ::
          {:ok, %{generation: struct(), current?: boolean()}} | {:error, term()}
  def commit_generation(source, rows, opts \\ [])
      when is_binary(source) and is_list(rows) do
    if valid_rows?(rows) do
      Repo.transaction(fn -> write_generation(source, rows, opts) end)
    else
      {:error, :invalid_rows}
    end
  end

  # The transaction body: generation, rows, pointer and receipt move together,
  # so a refresh can never leave a new cache without its receipt, or a moved
  # pointer without its rows.
  defp write_generation(source, rows, opts) do
    fetched_at = DateTime.utc_now()
    now = DateTime.truncate(fetched_at, :second)
    started_at = DateTime.truncate(Keyword.get(opts, :started_at) || fetched_at, :second)

    generation = insert_generation!(source, rows, opts, started_at, fetched_at)
    insert_advisory_rows!(source, generation.id, rows, now)

    current? = move_pointer!(source, generation.id, started_at, now)
    maybe_record_success(source, length(rows), current?, opts)

    %{generation: generation, current?: current?}
  end

  defp insert_generation!(source, rows, opts, started_at, fetched_at) do
    %Generation{}
    |> Generation.changeset(%{
      source: source,
      content_hash: Triage.Workspace.hash({source, rows}),
      row_count: length(rows),
      declared_count: Keyword.get(opts, :declared_count),
      complete: Keyword.get(opts, :complete, false) == true,
      catalog_version: Keyword.get(opts, :catalog_version),
      metadata: Keyword.get(opts, :metadata) || %{},
      started_at: started_at,
      fetched_at: fetched_at
    })
    |> Repo.insert!()
  end

  defp maybe_record_success(source, count, current?, opts) do
    if Keyword.get(opts, :receipt, false) == true do
      message = if current?, do: nil, else: "stored as history; a newer generation is current"
      {:ok, _} = record_receipt(source, true, count, message)
    end

    :ok
  end

  @doc """
  Low-level store used by tests, seeds and offline tooling.

  Rows are stored as a new generation that becomes current when it is the
  newest attempt, but the generation is never certified (`complete: false`) and
  no receipt is written: this path performs no source validation, so it must
  never be reported as a successful refresh. Live refreshes go through
  `commit_generation/3` with a validated `complete` flag and a receipt.
  """
  def replace_advisories(source, rows) when is_binary(source) and is_list(rows) do
    case commit_generation(source, rows, complete: false, receipt: false) do
      {:ok, %{generation: generation}} -> {:ok, generation.row_count}
      {:error, reason} -> {:error, reason}
    end
  end

  # Rows are already sanitized by the client; this only guards the low-level
  # API against entries no reader could ever resolve (no identity to look up).
  defp valid_rows?(rows) do
    Enum.all?(rows, fn row ->
      is_map(row) and is_binary(row_attr(row, :external_id)) and row_attr(row, :external_id) != ""
    end)
  end

  defp insert_advisory_rows!(_source, _generation_id, [], _now), do: :ok

  defp insert_advisory_rows!(source, generation_id, rows, now) do
    entries =
      Enum.map(rows, fn row ->
        %{
          source: source,
          external_id: row_attr(row, :external_id),
          summary: row_attr(row, :summary),
          published_at: truncate_datetime(row_attr(row, :published_at)),
          fetched_at: now,
          required_action: row_attr(row, :required_action),
          due_date: truncate_datetime(row_attr(row, :due_date)),
          known_ransomware: row_attr(row, :known_ransomware),
          generation_id: generation_id,
          inserted_at: now,
          updated_at: now
        }
      end)

    Repo.insert_all(Advisory, entries)
  end

  # The low-level API used changesets before, so atom- and string-keyed rows were
  # both accepted; keep both accepted here.
  defp row_attr(row, key) when is_map(row) do
    case Map.fetch(row, key) do
      {:ok, value} -> value
      :error -> Map.get(row, Atom.to_string(key))
    end
  end

  defp row_attr(_row, _key), do: nil

  defp truncate_datetime(nil), do: nil
  defp truncate_datetime(%DateTime{} = datetime), do: DateTime.truncate(datetime, :second)
  defp truncate_datetime(other), do: other

  # Serialized per source through a transaction-scoped advisory lock, so two
  # concurrent commits decide the pointer in a fixed order instead of racing the
  # upsert. `started_at` orders attempts; equal starts keep the later arrival.
  defp move_pointer!(source, generation_id, attempt_started_at, now) do
    Repo.query!("SELECT pg_advisory_xact_lock(hashtext($1))", [source])

    current =
      Repo.one(
        from(c in CurrentGeneration,
          join: g in Generation,
          on: g.id == c.generation_id,
          where: c.source == ^source,
          select: %{generation_id: c.generation_id, started_at: g.started_at}
        )
      )

    # A strictly older attempt never displaces a newer one. An equal start (the
    # pointer and the attempt share a second) keeps the later arrival: two
    # near-simultaneous refreshes of the same source converge instead of
    # deadlocking on the tie.
    newer? = is_nil(current) or DateTime.compare(attempt_started_at, current.started_at) != :lt

    if newer? do
      Repo.insert_all(
        CurrentGeneration,
        [%{source: source, generation_id: generation_id, inserted_at: now, updated_at: now}],
        on_conflict: [set: [generation_id: generation_id, updated_at: now]],
        conflict_target: [:source]
      )
    end

    newer?
  end

  @doc "Replaces the cached news rows for one source. Same atomic semantics as advisories."
  def replace_news(source, rows) when is_binary(source) and is_list(rows),
    do: replace_source(NewsItem, source, rows)

  # The one replacement path for a cached source. Advisory and news rows differ only in
  # their schema and their changeset, so both public functions share this body: one path
  # to validate, and the two caches cannot drift into different failure behaviour. The
  # replacement rows are inserted inside the deleting transaction, so a failure rolls the
  # source back to its previous contents instead of returning it empty.
  defp replace_source(schema, source, rows) do
    fetched_at = DateTime.utc_now()

    Repo.transaction(fn ->
      from(r in schema, where: r.source == ^source) |> Repo.delete_all()

      Enum.each(rows, fn row ->
        struct(schema)
        |> schema.changeset(Map.merge(row, %{source: source, fetched_at: fetched_at}))
        |> Repo.insert!()
      end)

      length(rows)
    end)
  end

  @doc "Validate an outbound link renders only safe https targets."
  def safe_link?(nil), do: true

  def safe_link?(link) when is_binary(link) do
    case URI.parse(link) do
      %URI{scheme: scheme} when scheme in @valid_schemes -> true
      _ -> false
    end
  end

  def safe_link?(_), do: false
end
