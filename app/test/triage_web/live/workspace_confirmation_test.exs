defmodule TriageWeb.WorkspaceConfirmationTest do
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Triage.Fixtures
  alias Triage.Decisions

  setup c do
    Triage.DataCase.reset_inventory!()
    image = image!("confirmation-audit")
    placement = placement!(image, "team-a", "prod")
    finding = finding!(image, "CVE-2099-5551")
    Map.merge(c, %{image: image, placement: placement, cve: finding.cve})
  end

  test "a partial save cannot commit a retained create_ticket draft without confirmation", c do
    keys = ~w(ADO_ORG_URL ADO_PROJECT ADO_PAT ADO_WORK_ITEM_TYPE)
    previous = Map.new(keys, &{&1, System.get_env(&1)})
    old_options = Application.get_env(:triage, :ado_req_options)
    test = self()

    on_exit(fn ->
      Enum.each(previous, fn {key, value} ->
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end)

      if old_options,
        do: Application.put_env(:triage, :ado_req_options, old_options),
        else: Application.delete_env(:triage, :ado_req_options)
    end)

    System.put_env(%{
      "ADO_ORG_URL" => "https://dev.azure.com/audit-synthetic",
      "ADO_PROJECT" => "Audit",
      "ADO_PAT" => "synthetic-only",
      "ADO_WORK_ITEM_TYPE" => "Task"
    })

    Application.put_env(:triage, :ado_req_options,
      adapter: fn request ->
        send(test, {:azure_called, request.method})
        {request, %Req.Response{status: 200, body: %{"id" => 8765}}}
      end
    )

    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_change(view, "draft", %{"decision" => %{"action" => "create_ticket"}})

    # Omitting the action must not commit the retained ticket action.
    render_submit(view, "save", %{"decision" => %{"reason" => "Already reviewed"}})

    assert has_element?(view, "#ticket-confirmation")
    refute_receive {:azure_called, _}
    assert Decisions.history_for_cve(c.cve) == []

    # Explicit confirmation still works and creates exactly one ticket.
    view |> element("#confirm-ticket") |> render_click()
    assert_receive {:azure_called, :post}
    assert [%{decision: "create_ticket"}] = Decisions.history_for_cve(c.cve)
  end

  test "a partial save cannot commit a retained accepted_risk draft without confirmation", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_change(view, "draft", %{"decision" => %{"action" => "accepted_risk"}})

    render_submit(view, "save", %{"decision" => %{"reason" => "Already reviewed"}})

    assert has_element?(view, "#confirm-risk")
    assert Decisions.history_for_cve(c.cve) == []

    view |> element("#confirm-risk") |> render_click()
    assert [%{decision: "accepted_risk"}] = Decisions.history_for_cve(c.cve)
  end
end
