defmodule Triage.DemoFleetTest do
  use Triage.DataCase, async: false
  import Triage.Fixtures
  alias Triage.{Decisions, Repo, Workspace}
  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}
  alias Triage.Seeds.DemoFleet

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  test "30 explicitly fictional CVEs span 18 workloads, seven teams and three environments" do
    assert %{added_cves: 30, workloads: 18, placements: 54} = DemoFleet.seed!()
    assert length(DemoFleet.cves()) == 30
    assert Repo.aggregate(Image, :count) == 18
    assert Repo.aggregate(ImagePlacement, :count) == 54
    assert Repo.aggregate(Finding, :count) >= 40
    assert length(Workspace.options().teams) == 7
    assert Enum.sort(Workspace.options().environments) == ~w(dev prod staging)

    assert Enum.all?(
             Repo.all(Finding),
             &(is_nil(&1.url) and String.starts_with?(&1.description, "SIMULATED DEMO"))
           )

    assert Enum.all?(Repo.all(Image), &String.starts_with?(&1.repository, "demo.invalid/"))
    exposures = Workspace.targets() |> Enum.map(& &1.exposure) |> Enum.uniq() |> Enum.sort()
    assert exposures == ~w(internal internet_exposed unknown)
  end

  test "all Review queues and varied lifecycle stories are available with current bindings" do
    DemoFleet.seed!()

    for mode <- ~w(needs progress accepted fixed) do
      assert Workspace.page(%{"page" => "review", "mode" => mode}).total > 0,
             "empty #{mode} queue"
    end

    assert Enum.all?(
             Workspace.targets(%{"cve" => "CVE-2099-9103"}),
             &(&1.coverage_state == :covered)
           )

    assert Enum.all?(Workspace.targets(%{"cve" => "CVE-2099-9113"}), & &1.needs_decision?)
    assert Enum.all?(Workspace.targets(%{"cve" => "CVE-2099-9124"}), & &1.needs_decision?)

    mixed =
      Workspace.targets(%{"cve" => "CVE-2099-9108"}) |> Map.new(&{&1.placement.environment, &1})

    assert mixed["prod"].needs_decision?
    assert mixed["staging"].decision.decision == "create_ticket"
    assert mixed["dev"].decision.decision == "accepted_risk"
    assert mixed["staging"].decision.metadata["ticket_url"] == nil
    assert mixed["staging"].decision.reason =~ "No Azure ticket was created"
    assert Repo.exists?(from f in Finding, where: f.reopen_count > 0)
    assert Repo.exists?(from f in Finding, where: not is_nil(f.resolved_at))
    assert length(Enum.uniq(Enum.map(Repo.all(Finding), &DateTime.to_date(&1.first_seen)))) >= 4
  end

  test "reruns do not reset presenter edits, retirements, decisions or timestamps" do
    DemoFleet.seed!()
    finding = Repo.one!(from f in Finding, where: f.cve == "CVE-2099-9101")
    Repo.update!(Ecto.Changeset.change(finding, description: "Presenter's edited scenario"))

    placement =
      Repo.one!(
        from p in ImagePlacement,
          where: p.image_id == ^finding.image_id and p.environment == "prod"
      )

    Repo.update!(Ecto.Changeset.change(placement, active: false))

    {:ok, _} =
      Decisions.record(%{
        cve: finding.cve,
        placement_id: placement.id,
        decision: "fixed",
        actor: "Presenter",
        reason: "Manual demo action"
      })

    before = snapshot()
    assert %{added_cves: 0} = DemoFleet.seed!(DateTime.add(DateTime.utc_now(), 30, :day))
    assert snapshot() == before
  end

  test "unrelated inventory and decisions are untouched" do
    image = image!("unrelated-demo-seed-test")
    placement = placement!(image, "existing-team", "prod")
    finding = finding!(image, "CVE-2088-4000")
    DemoFleet.seed!()
    assert Repo.get!(Image, image.id) == image
    assert Repo.get!(ImagePlacement, placement.id) == placement
    assert Repo.get!(Finding, finding.id) == finding
    assert Decisions.history_for_cve(finding.cve) == []
  end

  defp snapshot do
    Enum.map(
      [
        Image,
        ImagePlacement,
        Finding,
        FindingEvent,
        Decisions.Decision,
        Triage.Exposure.Evidence
      ],
      fn schema ->
        Repo.all(from row in schema, order_by: row.id)
      end
    )
  end
end
