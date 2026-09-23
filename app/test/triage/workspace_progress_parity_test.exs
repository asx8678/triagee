defmodule Triage.WorkspaceProgressParityTest do
  @moduledoc """
  W01a regression (discovered while hardening the AI binding): a work
  decision that expires inside the attention review window is review-due
  (band 1), not work-in-progress (band 2). The Elixir and SQL progress
  modes must agree, and pinning such an item must still render its review
  form instead of crashing the page read.
  """
  use Triage.DataCase, async: false
  import Triage.Fixtures
  alias Triage.{Attention, Workspace}
  alias Triage.Workspace.Commit

  setup do
    reset_inventory!()
    image = image!("progress-parity")
    prod = placement!(image, "alpha", "prod")
    finding = finding!(image, "CVE-2099-7001")
    %{prod: prod, cve: finding.cve}
  end

  test "a work decision expiring inside the review window is not in progress on either side", c do
    versions = Workspace.targets(%{"cve" => c.cve}) |> Map.new(&{&1.id, &1.fingerprint})

    assert {:ok, [decision]} =
             Commit.save(c.cve, [c.prod.id], versions, Ecto.UUID.generate(), %{
               "action" => "investigate",
               "owner" => "Team lead",
               "actor" => "Local reviewer",
               "reason" => "Investigation with a near-term expiry",
               "due_on" => Date.utc_today() |> Date.add(3) |> Date.to_iso8601()
             })

    assert DateTime.compare(decision.expires_at, DateTime.add(DateTime.utc_now(), 7, :day)) ==
             :lt

    targets = Workspace.targets(%{"cves" => [c.cve]})
    [target] = targets
    assert target.active?
    assert target.covered?
    assert target.decision.decision == "investigate"

    # Review-due (band 1) is a human step, not in-progress work (band 2).
    assert Attention.band(target) == 1
    assert Attention.reason(target) == "Exception expiring: review due"
    assert Workspace.select(targets, "progress") == []

    # The SQL twin agrees, and pinning the item renders instead of crashing.
    page = Workspace.page(%{"page" => "review", "mode" => "progress", "item" => c.cve})
    assert page.page_rows == []
    assert page.row.cve == c.cve
    assert page.total == 0
  end
end
