defmodule TriageWeb.TimelineFilters do
  @moduledoc """
  Parameter contract for the read-only timeline: the optional `owner` and
  `environment` display scope, the `weeks` window size, and the `cve` selection
  that opens the detail drawer.

  The scope value contract is not restated here. `owner`, `environment` and
  `cve` are all validated through `TriageWeb.FindingFilters.scope_value/1`,
  which is the published implementation of that contract, so the timeline
  cannot drift from the finding list about what a valid value is. The accepted
  *range* of `weeks` is enforced by `Triage.Timeline`, so an out-of-range value
  surfaces as a visible error rather than as a silently different window.

  Valid fields survive alongside rejected ones, so the page can still describe
  what it did not load. Invalid recognized input never loads a widened view.
  Scope filters are display scoping, never authorization.
  """

  use TriageWeb, :verified_routes

  alias Triage.Timeline
  alias TriageWeb.FindingFilters

  @recognized ~w(owner environment weeks cve events_after cases_after)
  @cursor_keys [:events_after, :cases_after]
  @weeks_digits ~r/\A[0-9]{1,2}\z/

  @typedoc "The validated timeline state: scope, window size and selection."
  @type filters :: %{
          owner: String.t() | nil,
          environment: String.t() | nil,
          weeks: pos_integer() | nil,
          cve: String.t() | nil,
          events_after: pos_integer() | nil,
          cases_after: pos_integer() | nil,
          invalid: [atom()]
        }

  @doc "The intentional All/default state: no scope restriction, default window."
  @spec defaults() :: filters()
  def defaults,
    do: %{
      owner: nil,
      environment: nil,
      weeks: nil,
      cve: nil,
      events_after: nil,
      cases_after: nil,
      invalid: []
    }

  @doc """
  Parses raw string-keyed URL params. Only the six recognized fields are
  considered; genuinely unrelated query metadata is ignored safely. The
  reserved `"filters"` wrapper key is invalid here, not harmless metadata.
  """
  @spec parse(term()) :: filters()
  def parse(params) when is_map(params) and not is_struct(params) do
    if Map.has_key?(params, "filters") do
      mark_invalid(defaults(), :filters)
    else
      defaults()
      |> put_value(:owner, Map.get(params, "owner"), &FindingFilters.scope_value/1)
      |> put_value(:environment, Map.get(params, "environment"), &FindingFilters.scope_value/1)
      |> put_value(:weeks, Map.get(params, "weeks"), &weeks_value/1)
      |> put_value(:cve, Map.get(params, "cve"), &cve_value/1)
      |> put_value(:events_after, Map.get(params, "events_after"), &cursor_value/1)
      |> put_value(:cases_after, Map.get(params, "cases_after"), &cursor_value/1)
      |> require_selection()
    end
  end

  # Total public boundary: any other incoming term (nil, numbers, lists,
  # booleans, binaries) surfaces the invalid state instead of raising and
  # killing the LiveView channel.
  def parse(_other), do: mark_invalid(defaults(), :filters)

  @doc """
  Parses a `filter` event. Exactly one plain `"filters"` wrapper level is
  supported, and a wrapper alongside recognized flat fields carrying real
  values is ambiguous and rejected. A flat event body - which is what the
  filter form actually sends - is parsed with the URL-param contract.
  """
  @spec parse_event(term()) :: filters()
  def parse_event(%{"filters" => filters} = params)
      when is_map(filters) and not is_struct(filters) and not is_struct(params) do
    if blank_flat_fields?(Map.take(params, @recognized)) do
      parse(filters)
    else
      mark_invalid(defaults(), :filters)
    end
  end

  def parse_event(%{"filters" => _other}), do: mark_invalid(defaults(), :filters)

  def parse_event(params) when is_map(params) and not is_struct(params), do: parse(params)

  def parse_event(_other), do: mark_invalid(defaults(), :filters)

  @doc """
  Atom-keyed query params for verified routes. Only validated values survive, so
  an invalid value is never written into a URL that would then reject it.
  """
  @spec query_params(term()) :: map()
  def query_params(%{owner: owner, environment: environment, weeks: weeks, cve: cve} = filters) do
    %{
      owner: emit_scope(owner),
      environment: emit_scope(environment),
      weeks: emit_weeks(weeks),
      cve: emit_scope(cve),
      events_after: emit_cursor(Map.get(filters, :events_after)),
      cases_after: emit_cursor(Map.get(filters, :cases_after))
    }
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
    |> drop_unselected_cursors()
  end

  def query_params(_other), do: %{}

  @doc """
  The verified timeline URL for these filters, with optional extra params.
  `nil` extra values are dropped, so a drawer link clears the selection by
  passing `%{cve: nil}`. Selecting a CVE or changing scope/window explicitly
  resets both history cursors; paging retains the other cursor and scope.
  """
  @spec path(term(), map()) :: String.t()
  def path(filters, extra \\ %{}) do
    qs =
      filters
      |> query_params()
      |> reset_history_cursors(extra)
      |> Map.merge(extra)
      |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)
      |> Map.new()
      |> drop_unselected_cursors()

    if map_size(qs) == 0 do
      ~p"/timeline"
    else
      ~p"/timeline?#{qs}"
    end
  end

  @doc "A human label for a rejected field, for the visible error state."
  def field_label(:owner), do: "team"
  def field_label(:environment), do: "environment"
  def field_label(:weeks), do: "window"
  def field_label(:cve), do: "CVE"
  def field_label(:events_after), do: "event history cursor"
  def field_label(:cases_after), do: "case history cursor"
  def field_label(:filters), do: "filters wrapper"
  def field_label(other), do: to_string(other)

  defp cursor_value(value) when value in [nil, ""], do: {:ok, nil}

  defp cursor_value(value) when is_binary(value) and byte_size(value) <= 19 do
    if Regex.match?(~r/\A[0-9]+\z/, value) do
      {id, ""} = Integer.parse(value)
      if Triage.Timeline.History.valid_cursor?(id), do: {:ok, id}, else: {:error, :cursor}
    else
      {:error, :cursor}
    end
  end

  defp cursor_value(_value), do: {:error, :cursor}

  defp emit_cursor(value) when is_integer(value) do
    if Triage.Timeline.History.valid_cursor?(value), do: Integer.to_string(value)
  end

  defp emit_cursor(_value), do: nil

  defp require_selection(%{cve: nil} = filters) do
    if Enum.any?(@cursor_keys, &(not is_nil(Map.get(filters, &1)))),
      do: mark_invalid(filters, :cve),
      else: filters
  end

  defp require_selection(filters), do: filters

  defp reset_history_cursors(params, extra) do
    if Enum.any?([:owner, :environment, :weeks, :cve], &Map.has_key?(extra, &1)),
      do: Map.drop(params, @cursor_keys),
      else: params
  end

  defp drop_unselected_cursors(params) do
    if Map.has_key?(params, :cve), do: params, else: Map.drop(params, @cursor_keys)
  end

  defp put_value(acc, field, raw, validator) do
    case validator.(raw) do
      {:ok, value} -> Map.put(acc, field, value)
      {:error, _reason} -> mark_invalid(acc, field)
    end
  end

  # Absent, nil or empty means the default window; otherwise 1-2 ASCII digits.
  # The range check belongs to the read model, which owns the window.
  defp weeks_value(nil), do: {:ok, nil}
  defp weeks_value(""), do: {:ok, nil}

  defp weeks_value(value) when is_binary(value) do
    if String.valid?(value) and Regex.match?(@weeks_digits, value) do
      case Integer.parse(value) do
        {weeks, ""} -> {:ok, weeks}
        _other -> {:error, :weeks}
      end
    else
      {:error, :weeks}
    end
  end

  defp weeks_value(_other), do: {:error, :weeks}

  # A blank CVE is not a selection: unlike a scope, there is no All choice.
  defp cve_value(nil), do: {:ok, nil}
  defp cve_value(""), do: {:ok, nil}

  defp cve_value(value) do
    case FindingFilters.scope_value(value) do
      {:ok, nil} -> {:error, :cve}
      other -> other
    end
  end

  defp emit_scope(value) do
    case FindingFilters.scope_value(value) do
      {:ok, trimmed} -> trimmed
      {:error, _reason} -> nil
    end
  end

  # The advertised options are the single source of truth for which window
  # sizes may be written into a URL.
  defp emit_weeks(weeks) when is_integer(weeks) do
    if Enum.any?(Timeline.window_options(), fn {_label, option} -> option == weeks end) do
      Integer.to_string(weeks)
    end
  end

  defp emit_weeks(_other), do: nil

  defp blank_flat_fields?(flat) do
    Enum.all?(flat, fn {_key, value} -> FindingFilters.scope_value(value) == {:ok, nil} end)
  end

  defp mark_invalid(acc, field), do: %{acc | invalid: [field | acc.invalid]}
end
