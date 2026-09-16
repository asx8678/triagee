defmodule TriageWeb.KevStatusComponentsTest do
  @moduledoc """
  Isolated rendering of the shared KEV source-status line: every cache state is
  plain text (never a colour or an implied claim), nil status is safe and
  explicit, and receipt text is escaped.
  """

  use ExUnit.Case, async: true
  use Phoenix.Component

  import Phoenix.LiveViewTest

  alias TriageWeb.UIComponents

  @attempted ~U[2026-09-12 10:30:00Z]

  defp receipt(overrides) do
    Map.merge(
      %{succeeded: true, attempted_at: @attempted, item_count: nil, message: nil},
      Map.new(overrides)
    )
  end

  test "nil and omitted status are nil-safe and state that no freshness is claimed" do
    for assigns <- [[id: "kev", status: nil], [id: "kev"]] do
      doc = component(&UIComponents.kev_source_status/1, assigns)

      assert count(doc, "#kev") == 1
      assert text(doc, "#kev") =~ "KEV cache status was not read for this view"
      assert text(doc, "#kev") =~ "no freshness is claimed"
      refute text(doc, "#kev") =~ "No refresh has been recorded"
      assert count(doc, "time") == 0
    end
  end

  test "never refreshed shows the source and whole-source count without inventing a result" do
    doc =
      component(&UIComponents.kev_source_status/1,
        id: "kev",
        status: %{source: "kev", rows: 0, receipt: nil}
      )

    assert text(doc, "#kev") =~ "KEV cache (source \"kev\")"
    assert text(doc, "#kev") =~ "0 cached advisories across the whole source"
    assert text(doc, "#kev") =~ "No refresh has been recorded yet"
    assert count(doc, "time") == 0
  end

  test "a populated successful refresh shows the result, time and feed count" do
    doc =
      component(&UIComponents.kev_source_status/1,
        id: "kev",
        status: %{source: "kev", rows: 2, receipt: receipt(item_count: 2)}
      )

    assert text(doc, "#kev") =~ "2 cached advisories across the whole source"
    assert text(doc, "#kev") =~ "not just the rows of this view"
    assert text(doc, "#kev") =~ "Last refresh succeeded"
    assert text(doc, "#kev") =~ "and reported 2 feed items"
    assert attrs(doc, "time", "datetime") == ["2026-09-12T10:30:00Z"]
  end

  test "a successful refresh of one feed item is grammatically exact" do
    doc =
      component(&UIComponents.kev_source_status/1,
        id: "kev",
        status: %{source: "kev", rows: 1, receipt: receipt(item_count: 1)}
      )

    assert text(doc, "#kev") =~ "1 cached advisory across the whole source"
    assert text(doc, "#kev") =~ "and reported 1 feed item"
  end

  test "an empty successful refresh is an honest outcome, never a clear signal" do
    doc =
      component(&UIComponents.kev_source_status/1,
        id: "kev",
        status: %{source: "kev", rows: 0, receipt: receipt(item_count: 0)}
      )

    assert text(doc, "#kev") =~ "reported 0 items — an empty feed report"
    assert text(doc, "#kev") =~ "not a claim that nothing is exploited"
    refute text(doc, "#kev") =~ "retained, not erased"
  end

  test "an uncounted successful refresh says the count was not recorded" do
    doc =
      component(&UIComponents.kev_source_status/1,
        id: "kev",
        status: %{source: "kev", rows: 1, receipt: receipt(item_count: nil)}
      )

    assert text(doc, "#kev") =~ "(item count not recorded)"
  end

  test "a failed last refresh retains the cache claim and escapes its message" do
    message = ~s{simulated <script>alert("x")</script> outage}

    doc =
      component(&UIComponents.kev_source_status/1,
        id: "kev",
        status: %{
          source: "kev",
          rows: 3,
          receipt: receipt(succeeded: false, message: message)
        }
      )

    assert text(doc, "#kev") =~ "3 cached advisories"
    assert text(doc, "#kev") =~ "Last refresh failed"
    assert text(doc, "#kev") =~ "previously cached advisories are retained, not erased"
    assert text(doc, "#kev") =~ "(#{message})"
    assert count(doc, "script") == 0
    assert count(doc, "time") == 1
  end

  test "the badge disclaimer is always present so a missing badge is never 'unexploited'" do
    for receipt_value <- [nil, receipt(succeeded: false, message: nil)] do
      doc =
        component(&UIComponents.kev_source_status/1,
          id: "kev",
          status: %{source: "kev", rows: 1, receipt: receipt_value}
        )

      assert text(doc, "#kev") =~ "Badges mark only advisories with a cached KEV row"
      assert text(doc, "#kev") =~ "a missing badge is never a claim"
    end
  end

  defp component(fun, assigns), do: fun |> render_component(assigns) |> LazyHTML.from_fragment()
  defp count(doc, selector), do: doc |> LazyHTML.query(selector) |> Enum.count()

  defp text(doc, selector),
    do: doc |> LazyHTML.query(selector) |> LazyHTML.text() |> String.trim()

  defp attrs(doc, selector, name), do: doc |> LazyHTML.query(selector) |> LazyHTML.attribute(name)
end
