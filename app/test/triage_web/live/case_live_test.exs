defmodule TriageWeb.CaseLiveTest do
  @moduledoc """
  Targeted PR 2 LiveView tests for the case flow: open-case visibility rules on
  the finding detail, frozen case rendering, review validation and save, exact
  retry vs token reuse, conflict handling preserving drafts and the original
  binding, the two-click evidence refresh confirmation, literal rendering of
  hostile text and malformed ids/params/events.

  Assertions use Phoenix.LiveViewTest/LazyHTML APIs only (element, has_element?,
  render_change, render_submit) — never raw-HTML matching.
  """

  use TriageWeb.ConnCase, async: true

  import Ecto.Query
  alias Triage.{Cases, Intel, Repo, Seeds}
  alias Triage.Inventory.Finding

  @env "prod"
  @scope %{owner: "alpha", environment: "prod"}

  setup do
    :ok = Seeds.seed()
    :ok
  end

  defp finding_id(package) do
    Repo.one!(
      from f in Finding,
        where: f.cve == "CVE-2026-60002" and f.package_name == ^package,
        select: f.id
    )
  end

  defp open_case(conn, package \\ "openssh-client", scope \\ @scope) do
    {:ok, view, _html} = live(conn, ~p"/findings/#{finding_id(package)}?#{scope}")

    assert {:error, {:live_redirect, %{to: to}}} =
             view |> element("#open-case-btn") |> render_click()

    {:ok, case_view, _html} = live(conn, to)
    {to, case_view}
  end

  test "the case's captured advisory opens the advisory detail under the saved scope", %{
    conn: conn
  } do
    {_to, case_view} = open_case(conn)

    expected = ~p"/cves/CVE-2025-1001?#{@scope}"

    # Scoped to the case's SAVED scope, so the aggregate a reviewer opens from the
    # case is the same team and environment the case is fixed to.
    assert has_element?(case_view, "#case-cve-action[href='#{expected}']")
    assert has_element?(case_view, "#case-cve-action", "Advisory detail")
  end

  test "the case header carries the cached KEV actionability it actually holds", %{conn: conn} do
    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2025-1001",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z],
          required_action: "Apply updates per vendor instructions.",
          due_date: ~U[2026-01-23 00:00:00Z],
          known_ransomware: true
        }
      ])

    {_to, case_view} = open_case(conn)

    assert has_element?(case_view, "#case-kev-badge", "Known exploited (KEV cache)")
    assert has_element?(case_view, "#case-kev", "Apply updates per vendor instructions.")
    assert has_element?(case_view, "#case-kev", "Known ransomware campaign use")
    assert has_element?(case_view, "#case-kev time")
  end

  defp case_id_of(to) do
    to |> URI.parse() |> Map.get(:path) |> String.split("/") |> Enum.at(2) |> String.to_integer()
  end

  defp snapshot_id_of(case_id) do
    {:ok, data} = Cases.get_case(case_id)
    Integer.to_string(data.case.current_snapshot_id)
  end

  defp submit(view, token, revision, snapshot_id, params) do
    view
    |> element("#review-form")
    |> render_submit(%{
      "review" => params,
      "meta" => %{
        "expected_revision" => revision,
        "expected_snapshot_id" => snapshot_id,
        "idempotency_token" => token
      }
    })
  end

  defp review_params(rationale \\ "Genuinely affected on this cluster; schedule a rebuild") do
    %{
      "applicability" => "affected",
      "priority" => "expedited_review",
      "next_action" => "rebuild_deploy",
      "rationale" => rationale
    }
  end

  test "open-case entry appears only with both an explicit team and environment", %{conn: conn} do
    id = finding_id("openssh-client")

    {:ok, view, _html} = live(conn, ~p"/findings/#{id}")
    refute has_element?(view, "#open-case-btn")
    assert has_element?(view, "#open-case-guidance")

    {:ok, view, _html} = live(conn, ~p"/findings/#{id}?owner=alpha")
    refute has_element?(view, "#open-case-btn")
    assert has_element?(view, "#open-case-guidance")

    {:ok, view, _html} = live(conn, ~p"/findings/#{id}?environment=#{@env}")
    refute has_element?(view, "#open-case-btn")
    assert has_element?(view, "#open-case-guidance")

    {:ok, view, _html} = live(conn, ~p"/findings/#{id}?owner=alpha&environment=#{@env}")
    assert has_element?(view, "#open-case-form")
    assert has_element?(view, "#open-case-btn")
    refute has_element?(view, "#open-case-guidance")
  end

  test "opening a case shows frozen evidence, scope, review form and history with stable ids", %{
    conn: conn
  } do
    {to, cview} = open_case(conn)

    assert URI.parse(to).path =~ "/cases/"

    assert has_element?(cview, "#case-banner", "local-operator")
    assert has_element?(cview, "#case-scope", "alpha")
    assert has_element?(cview, "#case-scope", @env)
    assert has_element?(cview, "#evidence-snapshot")
    assert has_element?(cview, "#evidence-snapshot", "openssh-client")
    assert has_element?(cview, "#evidence-snapshot", "registry.internal/app-a")
    assert has_element?(cview, "#evidence-snapshot", "Synthetic local inventory")
    assert has_element?(cview, "#review-form")
    assert has_element?(cview, "#case-timeline", "Case opened")
    assert has_element?(cview, "#reload-case")
    assert has_element?(cview, "#refresh-evidence-btn")
    refute has_element?(cview, "#case-conflict")
  end

  test "reopening the same scoped occurrence converges on the same case", %{conn: conn} do
    {to1, _cview} = open_case(conn)
    {to2, _cview} = open_case(conn)
    assert URI.parse(to1).path == URI.parse(to2).path
  end

  test "back link preserves owner, environment, search and suppressed filters", %{conn: conn} do
    qs = %{owner: "alpha", environment: @env, q: "openssh-client", suppressed: "1"}
    id = finding_id("openssh-client")
    {:ok, view, _html} = live(conn, ~p"/findings/#{id}?#{qs}")

    assert {:error, {:live_redirect, %{to: to}}} =
             view |> element("#open-case-btn") |> render_click()

    {:ok, cview, _html} = live(conn, to)

    assert {:error, {:live_redirect, %{to: back}}} =
             cview |> element("#back-to-finding") |> render_click()

    uri = URI.parse(back)
    assert uri.path == "/findings/#{id}"

    assert URI.decode_query(uri.query || "") == %{
             "owner" => "alpha",
             "environment" => @env,
             "q" => "openssh-client",
             "suppressed" => "1"
           }
  end

  test "review validation errors render inline and nothing is written", %{conn: conn} do
    {to, cview} = open_case(conn)
    case_id = case_id_of(to)
    snapshot_id = snapshot_id_of(case_id)

    submit(cview, Ecto.UUID.generate(), "1", snapshot_id, %{
      "applicability" => "affected",
      "priority" => "normal_review",
      "next_action" => "investigation",
      "rationale" => "   "
    })

    assert has_element?(cview, "#review-form p")
    refute has_element?(cview, "#case-timeline", "Manual assessment")

    {:ok, data} = Cases.get_case(case_id)
    assert data.reviews == []
  end

  test "saving a review appends to the timeline; exact retry replays; changed token reuse is rejected",
       %{conn: conn} do
    {to, cview} = open_case(conn)
    case_id = case_id_of(to)
    snapshot_id = snapshot_id_of(case_id)

    token = Ecto.UUID.generate()

    submit(cview, token, "1", snapshot_id, review_params())

    assert has_element?(cview, "#case-timeline", "Manual assessment")
    assert has_element?(cview, "#case-timeline", "Genuinely affected on this cluster")
    assert has_element?(cview, "#case-timeline", "Expedited review")
    assert has_element?(cview, "#case-timeline", "Rebuild and redeploy")

    {:ok, data} = Cases.get_case(case_id)
    assert length(data.reviews) == 1
    assert length(data.events) == 2

    # A late exact duplicate (queued double click) replays the original review.
    submit(cview, token, "1", snapshot_id, review_params())
    assert has_element?(cview, "[data-flash]", "Duplicate submission")

    {:ok, data} = Cases.get_case(case_id)
    assert length(data.reviews) == 1
    assert length(data.events) == 2

    # The same token with different content is rejected; the draft is kept.
    submit(cview, token, "1", snapshot_id, review_params("changed assessment"))
    assert has_element?(cview, "#token-reuse")
    assert has_element?(cview, "textarea", "changed assessment")

    {:ok, data} = Cases.get_case(case_id)
    assert length(data.reviews) == 1
  end

  test "a stale tab conflicts without rebasing: draft and original binding preserved, reload recovers",
       %{conn: conn} do
    {to, _cview} = open_case(conn)
    case_id = case_id_of(to)
    snapshot_id = snapshot_id_of(case_id)

    {:ok, view_a, _html} = live(conn, to)
    {:ok, view_b, _html} = live(conn, to)

    submit(view_a, Ecto.UUID.generate(), "1", snapshot_id, review_params())
    assert has_element?(view_a, "#case-timeline", "Manual assessment")

    # view_b still holds revision 1 and the original snapshot: submitting now
    # conflicts, keeps the draft and never silently rebases the binding.
    submit(view_b, Ecto.UUID.generate(), "1", snapshot_id, review_params("second operator draft"))
    assert has_element?(view_b, "#case-conflict")
    assert has_element?(view_b, "#case-conflict", "revision 1")
    assert has_element?(view_b, "textarea", "second operator draft")

    {:ok, data} = Cases.get_case(case_id)
    assert length(data.reviews) == 1

    # Explicit reload recovers, keeps the draft and clears the conflict.
    view_b |> element("#reload-case") |> render_click()
    refute has_element?(view_b, "#case-conflict")
    assert has_element?(view_b, "textarea", "second operator draft")
    assert has_element?(view_b, "#case-timeline", "Genuinely affected on this cluster")
  end

  test "evidence refresh needs explicit confirmation and keeps the draft", %{conn: conn} do
    {to, cview} = open_case(conn)
    case_id = case_id_of(to)

    refute has_element?(cview, "#refresh-evidence-confirm")

    cview
    |> element("#review-form")
    |> render_change(%{"review" => %{"rationale" => "draft under recheck"}})

    assert has_element?(cview, "textarea", "draft under recheck")

    cview |> element("#refresh-evidence-btn") |> render_click()
    assert has_element?(cview, "#refresh-evidence-confirm")
    assert has_element?(cview, "#refresh-evidence-confirm", "never submitted automatically")

    # Unchanged source: no new snapshot or event; confirmation clears; draft kept.
    cview |> element("#refresh-evidence-confirm-btn") |> render_click()
    refute has_element?(cview, "#refresh-evidence-confirm")
    assert has_element?(cview, "[data-flash]", "unchanged")
    assert has_element?(cview, "textarea", "draft under recheck")

    {:ok, data} = Cases.get_case(case_id)
    assert length(data.snapshots) == 1
    assert length(data.events) == 1
  end

  test "hostile rationale text renders literally in the timeline", %{conn: conn} do
    {to, cview} = open_case(conn)
    case_id = case_id_of(to)
    snapshot_id = snapshot_id_of(case_id)

    hostile = "<script>alert(1)</script> onerror=alert(2) \"quoted\" 'single'"
    submit(cview, Ecto.UUID.generate(), "1", snapshot_id, review_params(hostile))

    assert has_element?(cview, "#case-timeline", hostile)
    refute has_element?(cview, "script")

    # The frozen snapshot also carries the seeded hostile description as text.
    assert has_element?(cview, "#evidence-details", "never as markup")
  end

  test "malformed case ids fail visibly without crashing", %{conn: conn} do
    for id <- [
          "not-a-number",
          "1suffix",
          "-1",
          "0",
          "99999999999999999999",
          String.duplicate("9", 100)
        ] do
      {:ok, view, _html} = live(conn, "/cases/#{id}")
      assert has_element?(view, "#invalid-case")
    end
  end

  test "unknown case ids fail visibly", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/cases/99999999")
    assert has_element?(view, "#case-not-found")
  end

  test "query scope params never relabel the case; malformed ones fail visibly", %{conn: conn} do
    {to, _cview} = open_case(conn)
    path = URI.parse(to).path

    {:ok, view, _html} = live(conn, path <> "?owner=beta&environment=other-cluster")
    assert has_element?(view, "#case-scope", "alpha")
    assert has_element?(view, "#case-scope", "prod")
    refute has_element?(view, "#case-scope", "beta")

    {:ok, view, _html} = live(conn, path <> "?q=" <> String.duplicate("a", 300))
    assert has_element?(view, "#case-scope", "alpha")
    assert has_element?(view, "#invalid-back-scope")
  end

  test "malformed save events fail visibly without writing", %{conn: conn} do
    {to, cview} = open_case(conn)
    case_id = case_id_of(to)

    # Malformed binding metadata cannot be checked: rejected visibly.
    submit(cview, Ecto.UUID.generate(), "soon", "1", review_params())
    assert has_element?(cview, "#invalid-request")

    # A non-map review body is rejected visibly instead of crashing.
    cview |> element("#review-form") |> render_submit(%{"review" => "not-a-map"})
    assert has_element?(cview, "#invalid-request")

    {:ok, data} = Cases.get_case(case_id)
    assert data.reviews == []
  end

  test "mismatched query scope shows a notice; the back link carries only the case scope", %{
    conn: conn
  } do
    {to, _cview} = open_case(conn)
    path = URI.parse(to).path
    fid = finding_id("openssh-client")

    # Matching scope: no notice, and the back link preserves all four filters.
    {:ok, view, _html} =
      live(conn, path <> "?owner=alpha&environment=#{@env}&q=openssh-client&suppressed=1")

    refute has_element?(view, "#scope-mismatch")
    assert has_element?(view, "#case-scope", "alpha")
    assert has_element?(view, "#case-scope", @env)

    assert {:error, {:live_redirect, %{to: back}}} =
             view |> element("#back-to-finding") |> render_click()

    uri = URI.parse(back)
    assert uri.path == "/findings/#{fid}"

    assert URI.decode_query(uri.query || "") == %{
             "owner" => "alpha",
             "environment" => @env,
             "q" => "openssh-client",
             "suppressed" => "1"
           }

    # Mismatched owner and mismatched environment: visible #scope-mismatch, the
    # case keeps its own saved scope, and the back link carries ONLY the case
    # scope — never the mismatched (e.g. beta) query context.
    for query <- [
          "?owner=beta&environment=#{@env}&q=openssh-client&suppressed=1",
          "?owner=alpha&environment=other-cluster&q=openssh-client&suppressed=1",
          "?owner=beta&environment=other-cluster&q=openssh-client&suppressed=1"
        ] do
      {:ok, view, _html} = live(conn, path <> query)

      assert has_element?(view, "#case-scope", "alpha")
      assert has_element?(view, "#case-scope", @env)
      assert has_element?(view, "#scope-mismatch")

      assert {:error, {:live_redirect, %{to: back}}} =
               view |> element("#back-to-finding") |> render_click()

      uri = URI.parse(back)
      assert uri.path == "/findings/#{fid}"

      assert URI.decode_query(uri.query || "") == %{
               "owner" => "alpha",
               "environment" => @env
             }
    end
  end

  test "an invalid hidden idempotency token is rejected visibly without a crash", %{conn: conn} do
    # Astra defect: a browser-set hidden meta[idempotency_token]='bad\0token'
    # reached PostgreSQL and raised 22021, killing the LiveView. The server
    # only issues UUID tokens; anything else must render the visible
    # #invalid-request notice, keep the draft and write nothing.
    {to, cview} = open_case(conn)
    case_id = case_id_of(to)
    snapshot_id = snapshot_id_of(case_id)

    for token <- ["bad\0token", "", String.duplicate("x", 100), "12345", "server-token"] do
      submit(cview, token, "1", snapshot_id, review_params())

      assert has_element?(cview, "#invalid-request")
      assert has_element?(cview, "textarea", "Genuinely affected on this cluster")
    end

    {:ok, data} = Cases.get_case(case_id)
    assert data.reviews == []
    assert length(data.events) == 1
  end

  # PR2 regression: the back link must be reset explicitly on an invalid
  # back scope. assign_back_scope's malformed-filters branch previously left
  # the back_path from the last rendered (valid) route in the socket, so a
  # same-LiveView patch to another case — or to the same case with a malformed
  # query — kept the previous case's finding link behind the visible
  # #invalid-back-scope notice.
  test "an invalid back scope on a same-LiveView patch resets the back link to /findings; valid scope recovers it",
       %{conn: conn} do
    {to_a, _cview_a} = open_case(conn, "openssh-client", @scope)
    {to_b, _cview_b} = open_case(conn, "openssh-sftp-server", %{owner: "beta", environment: @env})
    fid_a = finding_id("openssh-client")
    fid_b = finding_id("openssh-sftp-server")
    path_a = URI.parse(to_a).path
    path_b = URI.parse(to_b).path

    # Case A renders from its valid saved scope: the back link targets its finding.
    {:ok, view, _html} = live(conn, path_a <> "?owner=alpha&environment=#{@env}")
    assert has_element?(view, "#back-to-finding[href^='/findings/#{fid_a}']")

    # Same-LiveView patch from case A to case B carrying a malformed owner
    # value: B stays readable from its saved scope, the invalid filter is
    # reported visibly, and the back link must reset to /findings — never
    # keep case A's previously rendered link.
    render_patch(view, path_b <> "?owner=%00")

    assert has_element?(view, "#invalid-back-scope")
    assert has_element?(view, "#case-scope", "beta")
    assert has_element?(view, "#case-scope", @env)
    assert has_element?(view, "#back-to-finding[href='/findings']")

    # Same case, valid -> invalid query: the case remains readable from its
    # saved scope, but the back link resets again instead of keeping the
    # prior rendered link.
    render_patch(view, path_b <> "?owner=beta&environment=#{@env}")
    assert has_element?(view, "#back-to-finding[href^='/findings/#{fid_b}']")

    render_patch(view, path_b <> "?q=" <> String.duplicate("a", 300))
    assert has_element?(view, "#invalid-back-scope")
    assert has_element?(view, "#case-scope", "beta")
    assert has_element?(view, "#back-to-finding[href='/findings']")

    # Valid navigation afterwards recovers the saved current case scope on
    # the back link, including preserved search and suppressed filters.
    render_patch(view, path_b <> "?owner=beta&environment=#{@env}&q=curl&suppressed=1")

    assert {:error, {:live_redirect, %{to: back}}} =
             view |> element("#back-to-finding") |> render_click()

    uri = URI.parse(back)
    assert uri.path == "/findings/#{fid_b}"

    assert URI.decode_query(uri.query || "") == %{
             "owner" => "beta",
             "environment" => @env,
             "q" => "openssh-sftp-server",
             "suppressed" => "1"
           }
  end

  # PR2 regression: handle_params' not-found branch previously only assigned
  # case_error and left the previously loaded case (and its binding, form and
  # streams) in the socket. A queued 'save' event on the invalid route then
  # persisted the previous case behind an invalid URL, and 'reload' /
  # confirmed refresh re-exposed it. Everything must fail closed.
  test "a queued save after a patch to an unknown case fails closed; nothing stale is written or re-exposed",
       %{conn: conn} do
    {to, cview} = open_case(conn)
    case_id = case_id_of(to)
    snapshot_id = snapshot_id_of(case_id)
    path = URI.parse(to).path

    # Navigate (patch) from the valid case to an unknown id: the invalid state
    # renders and no case data is visible.
    render_patch(cview, "/cases/99999999")

    assert has_element?(cview, "#case-not-found")
    refute has_element?(cview, "#case-banner")
    refute has_element?(cview, "#case-scope")
    refute has_element?(cview, "#evidence-snapshot")
    refute has_element?(cview, "#review-form")
    refute has_element?(cview, "#case-timeline")
    refute has_element?(cview, "#reload-case")

    # A queued 'save' still carrying the old, valid binding metadata must fail
    # closed: it may neither persist the previous case nor re-render it.
    cview
    |> render_submit("save", %{
      "review" => review_params(),
      "meta" => %{
        "expected_revision" => "1",
        "expected_snapshot_id" => snapshot_id,
        "idempotency_token" => Ecto.UUID.generate()
      }
    })

    assert has_element?(cview, "#case-not-found")
    refute has_element?(cview, "#case-banner")
    refute has_element?(cview, "#case-timeline", "Manual assessment")

    # Raw reload and a confirmed evidence refresh on the invalid route must
    # also fail closed.
    render_click(cview, "reload")
    assert has_element?(cview, "#case-not-found")
    refute has_element?(cview, "#case-banner")

    render_click(cview, "refresh_evidence_confirmed")
    assert has_element?(cview, "#case-not-found")
    refute has_element?(cview, "#case-banner")

    # Nothing was written: no review, no case event beyond the opening one,
    # no extra snapshot.
    {:ok, data} = Cases.get_case(case_id)
    assert data.reviews == []
    assert length(data.events) == 1
    assert length(data.snapshots) == 1

    # Valid recovery: the same LiveView returns to a usable case and a normal
    # save works against fresh state.
    render_patch(cview, path <> "?owner=alpha&environment=#{@env}")
    assert has_element?(cview, "#review-form")

    submit(cview, Ecto.UUID.generate(), "1", snapshot_id, review_params())
    assert has_element?(cview, "#case-timeline", "Manual assessment")

    {:ok, data} = Cases.get_case(case_id)
    assert length(data.reviews) == 1
  end

  # PR2 regression, malformed-id variant of the same stale-case hole, plus
  # mount guard parity: a fresh invalid mount must reject the same raw save.
  test "a queued save after a patch to a malformed case id fails closed; fresh invalid mounts reject it too",
       %{conn: conn} do
    {to, cview} = open_case(conn)
    case_id = case_id_of(to)
    snapshot_id = snapshot_id_of(case_id)

    render_patch(cview, "/cases/not-a-number")

    assert has_element?(cview, "#invalid-case")
    refute has_element?(cview, "#review-form")
    refute has_element?(cview, "#case-timeline")

    cview
    |> render_submit("save", %{
      "review" => review_params("queued on invalid route"),
      "meta" => %{
        "expected_revision" => "1",
        "expected_snapshot_id" => snapshot_id,
        "idempotency_token" => Ecto.UUID.generate()
      }
    })

    assert has_element?(cview, "#invalid-case")
    refute has_element?(cview, "#review-form")
    refute has_element?(cview, "#case-timeline", "Manual assessment")

    {:ok, data} = Cases.get_case(case_id)
    assert data.reviews == []

    # Mount guard parity: a fresh invalid mount also rejects the raw save.
    {:ok, fresh, _html} = live(conn, "/cases/9223372036854775808")

    assert has_element?(fresh, "#invalid-case")

    fresh
    |> render_submit("save", %{
      "review" => review_params("queued on fresh invalid mount"),
      "meta" => %{
        "expected_revision" => "1",
        "expected_snapshot_id" => snapshot_id,
        "idempotency_token" => Ecto.UUID.generate()
      }
    })

    assert has_element?(fresh, "#invalid-case")
    refute has_element?(fresh, "#review-form")

    {:ok, data} = Cases.get_case(case_id)
    assert data.reviews == []
    assert length(data.events) == 1
  end

  # PR 3: the queue entry link on the case detail is built only from the case's
  # saved owner/environment; it is never carried from URL parameters. On
  # invalid or unknown routes the whole valid-case section (including the
  # link) is not rendered, so it stays hidden automatically.
  test "case show links back to the queue scoped to the saved case scope", %{conn: conn} do
    {_to, cview} = open_case(conn)

    assert {:error, {:live_redirect, %{to: back}}} =
             cview |> element("#back-to-cases") |> render_click()

    uri = URI.parse(back)
    assert uri.path == "/cases"

    assert URI.decode_query(uri.query || "") == %{"owner" => "alpha", "environment" => @env}
  end

  test "invalid and unknown case routes show no back-to-cases link", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/cases/not-a-number")
    refute has_element?(view, "#back-to-cases")

    {:ok, view, _html} = live(conn, "/cases/99999999")
    refute has_element?(view, "#back-to-cases")
  end

  test "case route is registered" do
    paths = Phoenix.Router.routes(TriageWeb.Router) |> Enum.map(& &1.path)

    assert "/cases/:id" in paths
  end
end
