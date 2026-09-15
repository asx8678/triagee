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
        :known_ransomware
      ])
      |> validate_required([:source, :external_id, :fetched_at])
      |> unique_constraint([:source, :external_id])
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

  alias __MODULE__.{Advisory, NewsItem, RefreshReceipt}

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
    |> Repo.aggregate(:count)
  end

  @doc "Latest refresh receipt per source (for stale-status display)."
  def latest_receipts do
    from(r in RefreshReceipt,
      order_by: [asc: r.source, desc: r.attempted_at, desc: r.id],
      distinct: r.source
    )
    |> Repo.all()
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
  Replaces the cached advisory rows for one source.

  Atomic per source: the old rows are removed only inside the same
  transaction as the validated replacement set, so a partial failure can
  never leave the cache empty for a source. `rows` must already be sanitized
  normalized maps with `:source` supplying the source name — an empty list
  is a valid outcome ("source reported nothing"), NOT a cache wipe order on
  error; errors are recorded as receipts instead and never reach this call.
  """
  def replace_advisories(source, rows) when is_binary(source) and is_list(rows),
    do: replace_source(Advisory, source, rows)

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
