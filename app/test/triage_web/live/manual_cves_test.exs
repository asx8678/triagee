defmodule TriageWeb.ManualCvesTest do
  use TriageWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  alias Triage.ManualCves

  setup do
    previous = Application.get_env(:triage, :manual_cve_transport)

    Application.put_env(:triage, :manual_cve_transport, %{
      req: fn _ ->
        {:ok,
         %{
           status: 200,
           body:
             Jason.encode!(%{
               "vulnerabilities" => [
                 %{
                   "cve" => %{
                     "id" => "CVE-2024-3094",
                     "descriptions" => [%{"lang" => "en", "value" => "Example NVD description"}]
                   }
                 }
               ]
             })
         }}
      end
    })

    on_exit(fn ->
      if previous,
        do: Application.put_env(:triage, :manual_cve_transport, previous),
        else: Application.delete_env(:triage, :manual_cve_transport)
    end)

    :ok
  end

  test "fetch, preview, save and reload without creating affected inventory", %{conn: conn} do
    before = Triage.Workspace.targets()
    {:ok, view, _} = live(conn, "/?page=inventory")
    refute has_element?(view, "#manual-cves")
    assert has_element?(view, "#workspace-inventory")
    view |> element("#manual-cve-open") |> render_click()
    view |> form("#manual-cve-form", manual: %{cve: " cve-2024-3094 "}) |> render_submit()
    render_async(view)
    assert has_element?(view, "#manual-cve-preview", "Example NVD description")
    view |> element("#manual-cve-save") |> render_click()
    assert has_element?(view, "#research-CVE-2024-3094")
    {:ok, row} = ManualCves.fetch("CVE-2024-3094")
    assert {:ok, _} = ManualCves.save(row)
    assert Enum.count(ManualCves.list(), &(&1.external_id == row.external_id)) == 1
    assert Triage.Workspace.targets() == before
    {:ok, reloaded, _} = live(conn, "/?page=inventory")
    refute has_element?(reloaded, "#manual-cves")
    reloaded |> element("#manual-cve-open") |> render_click()
    assert has_element?(reloaded, "#research-CVE-2024-3094", "Example NVD description")
    reloaded |> element("button[phx-click=manual-close]") |> render_click()
    refute has_element?(reloaded, "#manual-cves")
  end

  test "invalid IDs never make a request and NVD failures do not produce a preview" do
    assert {:error, _} =
             ManualCves.fetch("not-a-cve", %{req: fn _ -> flunk("unexpected request") end})

    assert {:error, _} =
             ManualCves.fetch("CVE-2024-3094", %{req: fn _ -> {:ok, %{status: 429}} end})

    assert {:error, _} =
             ManualCves.fetch("CVE-2024-3094", %{
               req: fn _ -> {:ok, "{\"vulnerabilities\":[]}"} end
             })
  end
end
