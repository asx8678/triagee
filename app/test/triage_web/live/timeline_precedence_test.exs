defmodule TriageWeb.TimelinePrecedenceTest do
  @moduledoc """
  Timeline coverage must follow the same scoped/global chronology as the
  workspace: the newer effective decision decides, never the scope itself.
  """
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Triage.Fixtures
  alias Triage.{Repo, Workspace}

  setup c do
    Triage.DataCase.reset_inventory!()
    image = image!("precedence-audit")
    placement = placement!(image, "team-p", "prod")
    finding = finding!(image, "CVE-2099-5555")
    event!(finding, "appeared", at(5))
    Map.merge(c, %{placement: placement, cve: finding.cve})
  end

  defp record!(c, decision, decided_at, opts \\ []) do
    Repo.insert!(%Triage.Decisions.Decision{
      cve: c.cve,
      decision: decision,
      reason: "test",
      actor: "test",
      decided_at: decided_at,
      expires_at: Keyword.get(opts, :expires_at),
      placement_id: Keyword.get(opts, :placement_id)
    })
  end

  test "a newer whole-advisory decision ends a scoped whitelist on the chart", c do
    record!(c, "accepted_risk", at(4), placement_id: c.placement.id, expires_at: at(-10))

    record!(c, "fixed", at(1))

    [target] = Workspace.targets(%{"cve" => c.cve})
    assert target.decision.decision == "fixed"

    {:ok, view, _} = live(c.conn, "/timeline")
    assert_last_segment(view, c.cve, "tl-c-open")
  end

  test "a newer scoped decision ends an older whole-advisory whitelist", c do
    record!(c, "accepted_risk", at(4), expires_at: at(-10))

    record!(c, "fixed", at(1), placement_id: c.placement.id)

    [target] = Workspace.targets(%{"cve" => c.cve})
    assert target.decision.decision == "fixed"

    {:ok, view, _} = live(c.conn, "/timeline")
    assert_last_segment(view, c.cve, "tl-c-open")
  end

  test "newer scoped and global acceptances still cover the day", c do
    record!(c, "accepted_risk", at(4), expires_at: at(-10))

    record!(c, "accepted_risk", at(2), placement_id: c.placement.id, expires_at: at(-10))

    [target] = Workspace.targets(%{"cve" => c.cve})
    assert target.decision.decision == "accepted_risk"

    {:ok, view, _} = live(c.conn, "/timeline")
    assert_last_segment(view, c.cve, "tl-c-whitelisted")
  end

  defp assert_last_segment(view, cve, class) do
    last =
      view
      |> render()
      |> LazyHTML.from_document()
      |> LazyHTML.query("#tl-track-#{cve} .tl-c-seg")
      |> Enum.to_list()
      |> List.last()

    assert LazyHTML.attribute(last, "class") |> hd() =~ class
  end
end
