defmodule TriageWeb.FilterBarTest do
  @moduledoc """
  The shared filter bar exists so a filter control's position and width do not
  change from page to page. These tests pin the frame, not each page's query: the
  controls, the reset action, and the summary keep one order everywhere.
  """
  use TriageWeb.LegacyUICase, async: false

  import Phoenix.LiveViewTest

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  # Path, the bar's form id, and the reset control this page pairs with it.
  @bars [
    {"/triage/history", "#triage-filter-form", nil, "#triage-summary"},
    {"/findings", "#filter-form", "#reset-findings", "#findings-summary"},
    {"/timeline", "#timeline-form", "#timeline-reset", nil},
    {"/whats-new", "#whats-new-form", "#reset-activity", nil}
  ]

  defp count(document, selector) do
    document |> LazyHTML.query(selector) |> Enum.count()
  end

  test "every migrated page renders its controls inside one bar", %{conn: conn} do
    for {path, form_id, _reset, _summary} <- @bars do
      {:ok, _view, html} = live(conn, path)
      document = LazyHTML.from_document(html)

      # The bar is the form itself, so the shared `.filter-toolbar` sizing rules
      # reach its direct children on every page.
      assert count(document, "form#{form_id}.filter-toolbar") == 1,
             "#{path} does not render #{form_id} as a .filter-toolbar form"

      assert count(document, "form#{form_id} .fieldset") > 0,
             "#{path} renders no controls inside #{form_id}"

      # Nothing is left stranded outside the bar.
      assert count(document, ".filter-toolbar + .filter-toolbar") == 0
    end
  end

  test "a reset action lives in the bar, after the controls it resets", %{conn: conn} do
    for {path, form_id, reset_id, summary_id} <- @bars, reset_id do
      {:ok, _view, html} = live(conn, path)
      document = LazyHTML.from_document(html)

      assert count(document, "form#{form_id} .filter-bar-actions #{reset_id}") == 1,
             "#{path}: #{reset_id} is not in #{form_id}'s action group"

      # The order is fixed: every control, then the action group, then the
      # summary. Reset therefore never sits above or outside the controls it
      # resets, and the summary always describes the controls already applied.
      classes =
        document
        |> LazyHTML.query("form#{form_id} > *")
        |> LazyHTML.attribute("class")
        |> Enum.map(&(&1 || ""))

      actions_at = Enum.find_index(classes, &(&1 =~ "filter-bar-actions"))
      assert is_integer(actions_at), "#{path}: no action group in #{form_id}"

      controls_at = for {class, index} <- Enum.with_index(classes), class =~ "fieldset", do: index
      assert Enum.all?(controls_at, &(&1 < actions_at)), "#{path}: a control follows the reset"

      assert length(classes) - actions_at ==
               if(summary_id, do: 2, else: 1),
             "#{path}: #{inspect(classes)} does not end control…, actions, summary"
    end
  end

  test "a result summary renders as a direct child of the bar", %{conn: conn} do
    for {path, form_id, _reset, summary_id} <- @bars, summary_id do
      {:ok, _view, html} = live(conn, path)
      document = LazyHTML.from_document(html)

      # Direct-child status is what applies the shared summary sizing, and it is
      # why the summary slot is rendered without a wrapper.
      assert count(document, "form#{form_id} > #{summary_id}.filter-summary") == 1,
             "#{path}: #{summary_id} is not a direct .filter-summary child of #{form_id}"
    end
  end
end
