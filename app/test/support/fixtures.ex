defmodule Triage.Fixtures do
  @moduledoc """
  Shared test fixture entry point. Synthetic data only — see `Triage.Seeds`.

  The inventory helpers below are dated relative to today rather than to fixed
  calendar dates, so a windowed view (the CVE timeline) always contains them and
  the tests do not start failing once real time passes the fixture dates. Every
  helper writes directly through the repo; callers are responsible for starting
  from an empty inventory with `Triage.DataCase.reset_inventory!/0` when their
  assertions depend on counts.
  """

  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}
  alias Triage.Repo

  defdelegate seed(), to: Triage.Seeds

  @doc "Today in UTC: the reference date for the relative helpers below."
  def today, do: Date.utc_today()

  @doc "The UTC timestamp `days_before` days before today, at `time` (default 06:00)."
  def at(days_before, time \\ ~T[06:00:00]),
    do: DateTime.new!(Date.add(today(), -days_before), time, "Etc/UTC")

  @doc "An image whose digest is derived from `name`, so names stay unique per test."
  def image!(name) do
    Repo.insert!(%Image{
      digest: "sha256:fixture-" <> name,
      repository: "registry.test/" <> name,
      tag: "1.0"
    })
  end

  @doc """
  An active placement for `image` by default, so the case scope gate and the
  timeline's display scope both match it. Pass `active: false` for a retired one.
  """
  def placement!(image, owner, environment, active \\ true) do
    Repo.insert!(%ImagePlacement{
      image_id: image.id,
      namespace: "ns",
      owner: owner,
      environment: environment,
      active: active,
      first_seen: at(30),
      last_seen: at(0)
    })
  end

  @doc "A finding for `image`; `first_seen` defaults to three days ago."
  def finding!(image, cve, opts \\ []) do
    first_seen = Keyword.get(opts, :first_seen, at(3))

    Repo.insert!(%Finding{
      image_id: image.id,
      cve: cve,
      package_name: Keyword.get(opts, :package_name, "libssl"),
      package_version: Keyword.get(opts, :package_version, "1.0.0"),
      severity: Keyword.get(opts, :severity, "HIGH"),
      fix: Keyword.get(opts, :fix),
      description: Keyword.get(opts, :description),
      suppressed: Keyword.get(opts, :suppressed, false),
      first_seen: first_seen,
      last_seen: Keyword.get(opts, :last_seen, first_seen),
      resolved_at: Keyword.get(opts, :resolved_at),
      reopen_count: Keyword.get(opts, :reopen_count, 0)
    })
  end

  @doc "One recorded lifecycle event (`appeared`, `resolved` or `reopened`)."
  def event!(finding, kind, at) do
    Repo.insert!(%FindingEvent{finding_id: finding.id, event: kind, occurred_at: at})
  end

  @doc "The manual review fields exactly as the assessment form submits them."
  def review_attrs do
    %{
      "applicability" => "affected",
      "priority" => "normal_review",
      "next_action" => "investigation",
      "rationale" => "Synthetic fixture assessment."
    }
  end
end
