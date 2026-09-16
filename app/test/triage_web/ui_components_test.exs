defmodule TriageWeb.UIComponentsTest do
  use ExUnit.Case, async: true
  use Phoenix.Component

  import Phoenix.LiveViewTest
  import TriageWeb.UIComponents
  alias TriageWeb.{CoreComponents, Layouts, UIComponents}

  test "counted handles zero, singular and irregular plurals without interpreting markup" do
    for {n, expected} <- [{0, "0 packages"}, {1, "1 package"}, {2, "2 packages"}] do
      doc = component(&UIComponents.counted/1, count: n, singular: "package")
      assert doc |> LazyHTML.text() |> String.trim() == expected
    end

    doc = component(&UIComponents.counted/1, count: 2, singular: "advisory", plural: "advisories")
    assert doc |> LazyHTML.text() |> String.trim() == "2 advisories"

    doc = component(&UIComponents.counted/1, count: 1, singular: "<script>probe</script>")
    assert count(doc, "script") == 0
    assert doc |> LazyHTML.text() |> String.trim() == "1 <script>probe</script>"
  end

  test "technical disclosure preserves and copies the exact untrusted original" do
    value =
      "registry/team/" <>
        String.duplicate("long-image-", 12) <> "<script>alert('x')</script>&\"\nsha256:abc"

    doc =
      component(&UIComponents.technical_value/1, id: "image", label: "Image digest", value: value)

    assert count(doc, "#image details:not([open]) summary") == 1
    assert text(doc, "#image-full") == value
    assert attrs(doc, "#image-copy", "data-copy-value") == [value]
    assert attrs(doc, "#image-copy", "aria-label") == ["Copy exact Image digest"]
    assert count(doc, "#image-copy[phx-hook='CopyValue'][type='button']") == 1
    assert count(doc, "#image-feedback[role='status'][aria-live='polite']") == 1
    assert count(doc, "script") == 0
  end

  test "both technical variants preserve copy targets, hostile text and unique IDs" do
    value = ~s(sha256:<script>&"copy-me")

    for variant <- ["default", "compact"] do
      doc =
        component(&UIComponents.technical_value/1,
          id: "technical",
          label: "Digest",
          value: value,
          variant: variant
        )

      assert count(doc, "#technical") == 1
      assert count(doc, "#technical-copy") == 1
      assert count(doc, "#technical-feedback") == 1
      assert attrs(doc, "#technical-copy", "data-copy-feedback") == ["technical-feedback"]
      assert attrs(doc, "#technical-copy", "data-copy-value") == [value]
      assert attrs(doc, "#technical-copy", "aria-label") == ["Copy exact Digest"]
      assert count(doc, "#technical-feedback[phx-update='ignore'][aria-live='polite']") == 1
      assert text(doc, "#technical-full") == value
      assert count(doc, "script") == 0
      assert count(doc, ".technical-label.sr-only") == if(variant == "compact", do: 1, else: 0)
    end
  end

  test "missing technical values do not offer a fake copy action" do
    for value <- [nil, ""] do
      doc =
        component(&UIComponents.technical_value/1, id: "missing", label: "Digest", value: value)

      assert text(doc, "#missing") =~ "Not captured"
      assert count(doc, "button") == 0
    end
  end

  test "timestamps show UTC while retaining the exact offset and fractional original" do
    original = "2026-09-10T17:56:04.123456+02:00"
    doc = component(&UIComponents.timestamp/1, value: original)
    assert text(doc, "time") == "10 Sep 2026, 15:56 UTC"
    assert attrs(doc, "time", "datetime") == [original]
    assert attrs(doc, "time", "title") == [original]

    naive = component(&UIComponents.timestamp/1, value: ~N[2026-09-10 15:56:04])
    assert text(naive, "time") == "10 Sep 2026, 15:56 UTC"
    assert attrs(naive, "time", "datetime") == ["2026-09-10T15:56:04Z"]
  end

  test "missing and invalid timestamps stay explicitly unavailable, not invented dates" do
    missing = component(&UIComponents.timestamp/1, value: nil)
    assert count(missing, "time") == 0
    assert text(missing, "span") == "Not captured"
    invalid = component(&UIComponents.timestamp/1, value: "<script>bad time</script>")
    assert count(invalid, "time, script") == 0
    assert text(invalid, "span") =~ "Unavailable (original:"
  end

  test "only explicit severity kinds receive severity styling" do
    neutral = component(&UIComponents.status_badge/1, label: "Assessment recorded")
    assert count(neutral, ".status-badge-neutral") == 1
    high = component(&UIComponents.status_badge/1, label: "HIGH", kind: "severity")
    assert count(high, ".status-badge-high") == 1
    assert text(high, ".status-badge") == "HIGH"
    unknown = component(&UIComponents.status_badge/1, label: "Not reported", kind: "severity")
    assert count(unknown, ".status-badge-neutral") == 1
  end

  test "severity ramp exposes one distinct treatment class per level" do
    for {label, klass} <- [
          {"CRITICAL", "critical"},
          {"HIGH", "high"},
          {"MEDIUM", "medium"},
          {"LOW", "low"}
        ] do
      doc = component(&UIComponents.status_badge/1, label: label, kind: "severity")
      assert count(doc, ".status-badge-#{klass}") == 1
      assert text(doc, ".status-badge") == label
    end

    for label <- ["UNKNOWN", "Not reported"] do
      doc = component(&UIComponents.status_badge/1, label: label, kind: "severity")
      assert count(doc, ".status-badge-neutral") == 1
    end
  end

  test "compact technical value keeps the exact value and copy contract without the large label" do
    value = "sha256:" <> String.duplicate("a1", 40)

    doc =
      component(&UIComponents.technical_value/1,
        id: "cell",
        label: "Image digest",
        value: value,
        variant: "compact"
      )

    assert count(doc, "#cell.technical-value-compact") == 1
    assert count(doc, "#cell details.technical-compact:not([open])") == 1
    assert count(doc, "#cell .technical-label.sr-only") == 1
    assert text(doc, "#cell-full") == value
    assert attrs(doc, "#cell-copy", "data-copy-value") == [value]
    assert attrs(doc, "#cell-copy", "aria-label") == ["Copy exact Image digest"]

    missing =
      component(&UIComponents.technical_value/1,
        id: "cell-missing",
        label: "Image digest",
        value: nil,
        variant: "compact"
      )

    assert text(missing, "#cell-missing") =~ "Not captured"
    assert count(missing, "button") == 0
  end

  test "relative time is computed on the server from the exact timestamp" do
    now = ~U[2026-09-09 06:00:00Z]
    assert UIComponents.relative_time(~U[2026-09-09 05:59:30Z], now) == "just now"
    assert UIComponents.relative_time(~U[2026-09-09 05:30:00Z], now) == "30 minutes ago"
    assert UIComponents.relative_time(~U[2026-09-08 06:00:00Z], now) == "1 day ago"
    assert UIComponents.relative_time(~U[2026-08-05 06:00:00Z], now) == "5 weeks ago"
    assert UIComponents.relative_time(~N[2026-08-05 06:00:00], now) == "5 weeks ago"
    assert UIComponents.relative_time(~U[2026-09-09 06:10:00Z], now) == "in 10 minutes"
    assert UIComponents.relative_time(nil, now) == nil
    assert UIComponents.relative_time("<script>bad</script>", now) == nil
  end

  test "assessment state maps existing review data to a plain honest label" do
    assert UIComponents.assessment_state(%{latest_review: nil}) == "No assessment recorded"
    assert UIComponents.assessment_state(%{latest_review: %{id: 1}}) == "Assessment recorded"
    assert UIComponents.assessment_state(%{}) == "No assessment recorded"
  end

  test "header, notice and empty state expose semantic text and contextual actions" do
    doc = component(&patterns/1, %{})
    assert count(doc, ".page-header h1#patterns-title") == 1
    assert text(doc, ".page-header h1") == "Review workspace"
    assert count(doc, ".page-header .page-actions a[href='/cases']") == 1
    assert count(doc, "#warning.notice-warning") == 1
    assert count(doc, "#empty.empty-state h2") == 1
    assert count(doc, "#empty .page-actions a[href='/findings']") == 1
  end

  test "shell has one persistent notice, native mobile disclosure and all eight stable URLs" do
    doc = component(&shell/1, %{})
    assert count(doc, "a[href='#main-content']") == 1
    assert count(doc, "main#main-content[tabindex='-1']") == 1
    assert count(doc, "#navigation-menu > summary[aria-controls='primary-navigation']") == 1
    assert count(doc, "nav[aria-label='Primary'] a") == 8
    assert count(doc, "#nav-home[aria-current='page']") == 1
    assert text(doc, "#nav-home") == "Overview"
    assert text(doc, "#nav-whats-new") == "Activity"
    assert text(doc, "#nav-timeline") == "Timeline"
    assert count(doc, "#environment-notice") == 1
    assert count(doc, "#environment-notice .environment-summary") == 1
    assert count(doc, "#safety-details summary") == 1
    assert text(doc, "#safety-details") =~ "Live collection is disabled"
    assert text(doc, "#environment-notice") =~ ~r/filters are not\s+access control/
    assert text(doc, "#environment-notice") =~ "Live collection is disabled"
    refute text(doc, "#environment-notice") =~ "Synthetic data ·"
    assert count(doc, "img[src='/images/triage-wordmark-v2.png']") == 1
  end

  test "core field errors remain programmatically associated without replacing helper text" do
    doc =
      component(&CoreComponents.input/1,
        id: "rationale",
        name: "review[rationale]",
        type: "textarea",
        value: "",
        label: "Rationale",
        errors: ["Explain the evidence"],
        "aria-describedby": "rationale-help"
      )

    assert count(doc, "label[for='rationale']") == 1

    assert count(doc, "#rationale[aria-invalid='true'][aria-errormessage='rationale-errors']") ==
             1

    assert attrs(doc, "#rationale", "aria-describedby") == ["rationale-help"]
    assert text(doc, "#rationale-errors") =~ "Explain the evidence"
  end

  defp patterns(assigns) do
    ~H"""
    <.page_header
      id="patterns-title"
      title="Review workspace"
      eyebrow="Saved scope"
      subtitle="Inspect evidence."
    >
      <:actions><a href="/cases">Review queue</a></:actions>
    </.page_header>
    <.notice id="warning" kind="warning" title="Evidence changed">Recheck the snapshot.</.notice>
    <.empty_state id="empty" title="No cases" description="No saved cases match this scope.">
      <:actions><a href="/findings">Find an occurrence</a></:actions>
    </.empty_state>
    """
  end

  defp shell(assigns) do
    ~H"""
    <Layouts.app flash={%{}} active_page="home">
      <h1>Overview</h1>
    </Layouts.app>
    """
  end

  defp component(fun, assigns), do: fun |> render_component(assigns) |> LazyHTML.from_fragment()
  defp count(doc, selector), do: doc |> LazyHTML.query(selector) |> Enum.count()

  defp text(doc, selector),
    do: doc |> LazyHTML.query(selector) |> LazyHTML.text() |> String.trim()

  defp attrs(doc, selector, name), do: doc |> LazyHTML.query(selector) |> LazyHTML.attribute(name)
end
