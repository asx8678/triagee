defmodule TriageWeb.FilterAssigns do
  @moduledoc "Pure scope-form and cleared pagination data; views retain queries, errors and stream resets."

  @doc "Build a scope form without coercing, dropping or widening the selected values."
  def filter_form(filters) do
    Phoenix.Component.to_form(%{
      "owner" => filters[:owner],
      "environment" => filters[:environment]
    })
  end

  @doc "The shared pagination reset for the review queue and activity feed."
  def cleared_page do
    %{page_count: 0, has_more?: false, next_before_id: nil, cursor: nil}
  end
end
