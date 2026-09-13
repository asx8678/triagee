defmodule Triage.ImportFlowTest do
  use Triage.DataCase, async: false
  alias Triage.{Import, ImportFlow, Repo}
  alias Triage.Inventory.Image

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  defp json do
    Jason.encode!(%{
      format: "triage.snapshot",
      version: 1,
      source: "synthetic historical fixture",
      generated_at: "2026-09-09T06:00:00Z",
      images: [
        %{
          digest: "sha256:" <> String.duplicate("c", 64),
          repository: "synthetic/example",
          tag: "historical",
          description: nil,
          placements: [],
          findings: []
        }
      ]
    })
  end

  test "preview writes nothing; explicit bound apply reconciles" do
    assert {:ok, prepared} = ImportFlow.prepare(json())
    assert Repo.aggregate(Image, :count) == 0
    assert {:error, :invalid_confirmation} = ImportFlow.apply(prepared, prepared.nonce, "false")

    assert {:error, :invalid_confirmation} =
             ImportFlow.apply(prepared, Ecto.UUID.generate(), "true")

    assert Repo.aggregate(Image, :count) == 0
    assert {:ok, report} = ImportFlow.apply(prepared, prepared.nonce, "true")
    assert report.summary.images.create == 1
    assert Repo.aggregate(Image, :count) == 1
    assert {:error, :stale_preview} = ImportFlow.apply(prepared, prepared.nonce, "true")
  end

  test "intervening writer makes preview stale without overwriting its work" do
    {:ok, prepared} = ImportFlow.prepare(json())
    assert {:ok, _} = Import.apply(prepared.snapshot)
    image = Repo.one!(Image)
    image |> Ecto.Changeset.change(repository: "changed/local") |> Repo.update!()
    assert {:error, :stale_preview} = ImportFlow.apply(prepared, prepared.nonce, "true")
    assert Repo.one!(Image).repository == "changed/local"
  end

  test "full detail changes are stale even when action counts are identical" do
    {:ok, initial} = ImportFlow.prepare(json())
    {:ok, _} = Import.apply(initial.snapshot)
    image = Repo.one!(Image)
    image |> Ecto.Changeset.change(repository: "first/local") |> Repo.update!()
    {:ok, prepared} = ImportFlow.prepare(json())
    # Changing a database ID affects report identity while retaining update counts.
    Repo.delete!(Repo.one!(Image))
    {:ok, _} = Import.apply(initial.snapshot)
    Repo.one!(Image) |> Ecto.Changeset.change(repository: "second/local") |> Repo.update!()
    {:ok, fresh} = ImportFlow.prepare(json())
    assert prepared.report.summary == fresh.report.summary
    refute prepared.fingerprint == fresh.fingerprint
    assert {:error, :stale_preview} = ImportFlow.apply(prepared, prepared.nonce, "true")
  end

  test "malformed, oversized and deeply nested input is rejected" do
    for input <- [
          nil,
          %{},
          "{bad secret",
          String.duplicate(" ", 1_000_001),
          String.duplicate("[", 33) <> String.duplicate("]", 33)
        ] do
      assert {:error, :invalid_snapshot} = ImportFlow.prepare(input)
    end

    assert {:error, :invalid_confirmation} = ImportFlow.apply(%{}, "forged", "true")
    {:ok, prepared} = ImportFlow.prepare(json())

    assert {:error, :invalid_confirmation} =
             ImportFlow.apply(%{prepared | digest: "forged"}, prepared.nonce, "true")

    assert Repo.aggregate(Image, :count) == 0
  end

  test "same ID and same action report with changed metadata is stale" do
    {:ok, initial} = ImportFlow.prepare(json())
    {:ok, _} = Import.apply(initial.snapshot)
    Repo.one!(Image) |> Ecto.Changeset.change(repository: "first/local") |> Repo.update!()
    {:ok, prepared} = ImportFlow.prepare(json())
    Repo.one!(Image) |> Ecto.Changeset.change(repository: "second/local") |> Repo.update!()
    {:ok, fresh} = ImportFlow.prepare(json())

    assert Map.delete(prepared.report, :inventory_fingerprint) ==
             Map.delete(fresh.report, :inventory_fingerprint)

    assert {:error, :stale_preview} = ImportFlow.apply(prepared, prepared.nonce, "true")
    assert Repo.one!(Image).repository == "second/local"
  end

  test "malformed bindings perform no SQL" do
    {:ok, prepared} = ImportFlow.prepare(json())
    handler = "flow-no-sql-#{Ecto.UUID.generate()}"
    parent = self()

    :telemetry.attach(
      handler,
      [:triage, :repo, :query],
      fn _, _, _, _ -> send(parent, :unexpected_sql) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)

    for bad <- [
          nil,
          %{},
          Map.put(prepared, :extra, true),
          %{prepared | snapshot: []},
          %{prepared | digest: "forged"},
          %{prepared | fingerprint: "forged"},
          %{prepared | report: []},
          %{prepared | nonce: "invalid"}
        ] do
      assert {:error, :invalid_confirmation} = ImportFlow.apply(bad, prepared.nonce, "true")
    end

    for {nonce, ack} <- [{%{}, "true"}, {prepared.nonce, true}, {nil, "true"}] do
      assert {:error, :invalid_confirmation} = ImportFlow.apply(prepared, nonce, ack)
    end

    refute_received :unexpected_sql
  end

  test "depth lexer respects escaped quotes and brackets inside strings" do
    raw =
      Jason.decode!(json()) |> Map.put("source", "brackets [ { and escaped quote \" and slash \\")

    assert {:ok, _} = ImportFlow.prepare(Jason.encode!(raw))

    assert {:error, :invalid_snapshot} =
             ImportFlow.prepare(String.duplicate("[", 33) <> "0" <> String.duplicate("]", 33))
  end

  test "bounded upload reader closes file and permits temporary-file cleanup" do
    path = Path.join(System.tmp_dir!(), "triage-import-#{Ecto.UUID.generate()}.json")
    on_exit(fn -> File.rm(path) end)
    File.write!(path, String.duplicate("x", ImportFlow.max_bytes() + 1))
    assert {:error, :invalid_snapshot} = ImportFlow.read_upload(path)
    assert :ok = File.rm(path)
  end
end
