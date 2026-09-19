defmodule Triage.PresentationSeedsTest do
  use Triage.DataCase, async: false
  alias Triage.{Repo, Seeds}
  alias Triage.Inventory.{Finding, FindingEvent}

  test "presentation histories have varied timing and repeat without duplicates" do
    Triage.DataCase.reset_inventory!()
    assert :ok = Seeds.seed()
    findings = Repo.all(from f in Finding, where: like(f.cve, "CVE-2099-90%"))
    assert length(findings) == 27
    assert Enum.all?(findings, &is_nil(&1.url))
    four = Enum.find(findings, &(&1.cve == "CVE-2099-9004"))
    assert DateTime.diff(four.resolved_at, four.first_seen) == 4 * 3600
    assert length(Enum.uniq(Enum.map(findings, &DateTime.to_date(&1.first_seen)))) >= 5

    for {cve, hours} <- [{"CVE-2099-9001", 2}, {"CVE-2099-9002", 5}] do
      finding = Enum.find(findings, &(&1.cve == cve))
      decision = Repo.one!(from d in Triage.Decisions.Decision, where: d.cve == ^cve)
      assert DateTime.diff(decision.decided_at, finding.first_seen) == hours * 3600
      assert is_nil(finding.resolved_at)
    end

    counts =
      {Repo.aggregate(Finding, :count), Repo.aggregate(FindingEvent, :count),
       Repo.aggregate(Triage.Decisions.Decision, :count)}

    assert :ok = Seeds.seed()

    assert counts ==
             {Repo.aggregate(Finding, :count), Repo.aggregate(FindingEvent, :count),
              Repo.aggregate(Triage.Decisions.Decision, :count)}
  end
end
