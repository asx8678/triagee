defmodule TriageWeb.UIReadabilityBoundaryTest do
  use TriageWeb.LegacyUICase, async: true

  import Ecto.Query
  alias Triage.{Cases, Repo, Seeds}
  alias Triage.Inventory.Finding

  test "all ten route mounts, scoped navigation and invalid filters leave stored rows unchanged",
       %{conn: conn} do
    :ok = Seeds.seed()
    id = Repo.one!(from f in Finding, where: f.package_name == "openssh-client", select: f.id)
    {:ok, opened} = Cases.open_case(id, owner: "alpha", environment: "prod")
    case_id = opened.case.id
    before = fingerprints()

    assert conn
           |> get("/")
           |> html_response(200)
           |> LazyHTML.from_document()
           |> LazyHTML.query("h1")
           |> Enum.count() == 1

    for path <- [
          "/findings",
          "/findings/#{id}?owner=alpha&environment=prod&q=openssh-client",
          "/cases",
          "/cases/#{case_id}?owner=beta&environment=other",
          "/whats-new",
          "/imports",
          "/replay",
          "/replay/history",
          "/statistics",
          "/findings?owner=alpha&q=no-such-synthetic-package",
          "/findings?owner[]=invalid",
          "/cases?environment[]=invalid",
          "/whats-new?before=invalid"
        ] do
      {:ok, view, _} = live(conn, path)
      assert has_element?(view, "#main-content")
      assert has_element?(view, "#primary-navigation")
      assert fingerprints() == before, "passive route changed records: #{path}"
    end

    {:ok, data} = Cases.get_case(case_id)
    assert data.case.owner == "alpha"
    assert data.case.environment == "prod"
    assert data.case.revision == 1
    assert data.reviews == []
  end

  defp fingerprints do
    for table <-
          ~w(images image_placements findings finding_events review_cases review_evidence_snapshots review_reviews review_case_events replay_runs),
        into: %{} do
      %{rows: [[count, digest]]} =
        Ecto.Adapters.SQL.query!(
          Repo,
          "SELECT count(*), md5(COALESCE(string_agg(row_to_json(t)::text, '|' ORDER BY id), '')) FROM #{table} t",
          []
        )

      {table, {count, digest}}
    end
  end
end
