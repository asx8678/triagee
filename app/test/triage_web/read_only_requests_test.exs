defmodule TriageWeb.ReadOnlyRequestsTest do
  @moduledoc """
  Boundary test for the read-only requirement of the intelligence plan: ordinary GET
  requests must never reach the network and must never write to the database.

  Network access is asserted structurally, not by observation. With the default
  configuration the intel client's own default transport is
  `fn _url -> {:error, :intel_disabled} end`, so a request-time fetch is impossible
  rather than merely unobserved. Writes are asserted by a whole-database row-count
  fingerprint taken before and after rendering the read routes.
  """
  use TriageWeb.ConnCase, async: false

  import Ecto.Query
  import Phoenix.LiveViewTest

  alias Triage.{Cases, Intel, Repo, Seeds}
  alias Triage.Inventory.Finding

  @live_routes [
    "/findings",
    "/cases",
    "/whats-new",
    "/timeline",
    "/replay",
    "/replay/history",
    "/imports"
  ]

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Seeds.seed()
    # Seeds create no review cases, so open one: the case detail route is then
    # exercised instead of being skipped by a missing fixture.
    open_case!()
    :ok
  end

  defp open_case! do
    finding_id =
      Repo.one!(
        from(f in Finding,
          where: f.cve == "CVE-2025-1001",
          order_by: [asc: f.id],
          limit: 1,
          select: f.id
        )
      )

    {:ok, %{case: review_case}} =
      Cases.open_case(finding_id, owner: "alpha", environment: "prod-cluster-1")

    review_case
  end

  test "the default intel transport cannot reach the network" do
    refute Intel.Config.enabled?()
    assert Intel.Config.enabled_sources() == []
    assert Intel.Client.fetch(:kev) == {:error, :intel_disabled}
    assert Intel.Client.fetch({:nvd, "CVE-2024-4004"}) == {:error, :intel_disabled}
  end

  test "every read route leaves every table unchanged", %{conn: conn} do
    details = detail_routes()
    # Coverage cannot silently shrink to the controller route.
    assert length(details) == 3

    before = table_fingerprint()

    assert conn |> get(~p"/") |> html_response(200)

    for path <- @live_routes ++ details do
      assert {:ok, _view, _html} = live(conn, path)
    end

    after_fingerprint = table_fingerprint()

    assert after_fingerprint == before

    # A refresh always records a receipt, so an unchanged receipt count is direct
    # evidence that no refresh ran while these requests were served.
    assert after_fingerprint["intel_refresh_receipts"] == before["intel_refresh_receipts"]
  end

  defp detail_routes do
    [
      "/cves/CVE-2024-4004"
      | one_id_route("select id from findings order by id limit 1", "/findings")
    ] ++
      one_id_route("select id from review_cases order by id limit 1", "/cases")
  end

  defp one_id_route(sql, prefix) do
    case Repo.query!(sql) do
      %{rows: [[id]]} -> ["#{prefix}/#{id}"]
      _ -> []
    end
  end

  defp table_fingerprint do
    %{rows: rows} = Repo.query!("select tablename from pg_tables where schemaname = 'public'")

    rows
    |> List.flatten()
    |> Enum.reject(&(&1 == "schema_migrations"))
    |> Map.new(fn table -> {table, count_rows(table)} end)
  end

  defp count_rows(table) do
    %{rows: [[count]]} = Repo.query!("select count(*) from \"#{table}\"")
    count
  end
end
