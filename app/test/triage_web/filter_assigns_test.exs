defmodule TriageWeb.FilterAssignsTest do
  use ExUnit.Case, async: true

  alias TriageWeb.FilterAssigns

  test "scope form keeps values without adding cursor or view-specific filters" do
    for owner <- [nil, "", "team <unknown>", "invalid\nteam"] do
      form =
        FilterAssigns.filter_form(%{owner: owner, environment: "prod", before_id: 42, weeks: 8})

      assert form.params == %{"owner" => owner, "environment" => "prod"}
      assert form[:owner].value == owner
      assert form[:environment].value == "prod"
    end
  end

  test "cleared pagination cannot retain stale rows or navigation" do
    old = %{
      page_count: 10,
      has_more?: true,
      next_before_id: 50,
      cursor: 70,
      filters: %{owner: "alpha"}
    }

    cleared = FilterAssigns.cleared_page()
    assert cleared == %{page_count: 0, has_more?: false, next_before_id: nil, cursor: nil}
    assert Map.merge(old, cleared).filters == %{owner: "alpha"}
    refute Map.has_key?(cleared, :queue_error)
    refute Map.has_key?(cleared, :feed_error)
  end
end
