defmodule TriageWeb.PageControllerTest do
  use TriageWeb.LegacyUICase

  test "GET / is the vulnerabilities workspace", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()
    assert LazyHTML.query(document, "title") |> LazyHTML.text() == "Vulnerabilities · Triage"
    assert LazyHTML.query(document, "h1") |> LazyHTML.text() == "Vulnerabilities"
    assert Enum.count(LazyHTML.query(document, "#filter-form")) == 1

    assert Enum.count(LazyHTML.query(document, "#nav-findings[href='/'][aria-current='page']")) ==
             1

    assert Enum.count(LazyHTML.query(document, ".nav-group-primary a")) == 3
    assert Enum.empty?(LazyHTML.query(document, ".nav-group-tools[open]"))
    assert Enum.count(LazyHTML.query(document, "#environment-notice")) == 1
  end
end
