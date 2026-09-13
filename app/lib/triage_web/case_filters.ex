defmodule TriageWeb.CaseFilters do
  @moduledoc """
  Validation and normalization contract for the read-only review queue's URL
  and filter-event parameters: `owner`, `environment` and the `before`
  keyset cursor.

  Scope filters are display scoping, never authorization. Only the two saved
  case scope fields are validated here, against the same value contract as
  `TriageWeb.FindingFilters` (raw valid UTF-8, no NUL/C0/DEL before trimming,
  at most 120 characters after trimming; blank is the intentional All
  choice). The raw queue map is never passed through `FindingFilters.parse/1`
  wholesale, so a malformed unrelated `q`/`suppressed`/`return_to` value can
  never invalidate the queue view. Malformed recognized values surface in
  `:invalid` so the LiveView renders a visible error with no rows instead of
  coercing, truncating, silently unscoping or crashing.

  The `before` cursor is a position, not an authorization token: absent,
  nil or empty means newest; otherwise exactly 1-19 ASCII decimal digits
  representing a positive PostgreSQL bigint. Signs, whitespace, floats,
  oversized text, non-binary terms, invalid UTF-8, control characters, zero
  and overflow are rejected visibly.
  """

  @recognized ~w(owner environment before)
  @unsafe_text ~r/[\x00-\x1F\x7F]/
  @cursor_digits ~r/\A[0-9]{1,19}\z/
  # int8 max is exactly 2^63 - 1: the same positive bigint bound as the
  # domain layer's id guards.
  @cursor_max 9_223_372_036_854_775_807

  alias TriageWeb.FindingFilters

  @doc "The intentional All/newest state: no scope restrictions, no cursor."
  @typedoc """
  The validated queue state: the saved-scope filters, the keyset position, and
  the recognized fields that were rejected.
  """
  @type filters :: %{
          owner: String.t() | nil,
          environment: String.t() | nil,
          before_id: pos_integer() | nil,
          invalid: [atom()]
        }

  @spec defaults() :: filters()
  def defaults do
    %{owner: nil, environment: nil, before_id: nil, invalid: []}
  end

  @doc """
  Parses raw string-keyed URL params. Recognized fields are `owner`,
  `environment` and `before` only; genuinely unrelated query metadata is
  ignored safely and never invalidates the queue. The reserved `"filters"`
  wrapper key is invalid in URL parsing, not harmless metadata.
  """
  # Plain string-keyed maps only: structs are rejected explicitly instead of
  # slipping through is_map/1 as a silent All.
  @spec parse(term()) :: filters()
  def parse(params) when is_map(params) and not is_struct(params) do
    if Map.has_key?(params, "filters") do
      mark_invalid(defaults(), :filters)
    else
      # Extract the scope values FIRST and validate ONLY those two against
      # the FindingFilters value contract — never the whole raw map, so a
      # malformed unrelated q/suppressed/return_to value is ignored.
      scope =
        FindingFilters.parse(%{
          "owner" => Map.get(params, "owner"),
          "environment" => Map.get(params, "environment")
        })

      case cursor_value(Map.get(params, "before")) do
        {:ok, before_id} ->
          %{
            defaults()
            | owner: scope.owner,
              environment: scope.environment,
              before_id: before_id,
              invalid: scope.invalid
          }

        {:error, :before} ->
          %{
            defaults()
            | owner: scope.owner,
              environment: scope.environment,
              invalid: [:before | scope.invalid]
          }
      end
    end
  end

  # Total public boundary: any other incoming term (nil, numbers, lists,
  # booleans, binaries) surfaces the invalid state instead of raising and
  # killing the LiveView channel.
  def parse(_other), do: mark_invalid(defaults(), :filters)

  @doc """
  Parses a `filter` event. Exactly one plain `"filters"` wrapper level is
  supported: a legitimate wrapper event is unwrapped once and validated with
  the URL-param contract. Rejected instead of silently unwrapped or ignored:
  a non-map wrapper, a nested `"filters"` key (reserved; `parse/1` rejects
  it) and ambiguous combinations where a wrapper appears alongside recognized
  flat fields carrying real values — including a nonblank flat `before`
  cursor. Genuine event metadata such as `"_target"` never reaches these
  checks. Non-map event bodies surface the invalid state instead of raising.
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

  # Structs are non-plain maps at every entry point: a struct wrapper value
  # is rejected here rather than unwrapped, and a flat struct event body — or
  # a struct OUTER body carrying a "filters" key — falls through to the
  # invalid state instead of being unwrapped or parsed like a URL map.
  def parse_event(%{"filters" => _other}), do: mark_invalid(defaults(), :filters)

  def parse_event(params) when is_map(params) and not is_struct(params),
    do: parse(params)

  def parse_event(_other), do: mark_invalid(defaults(), :filters)

  @doc """
  Atom-keyed query params for verified routes. Emits ONLY validated non-nil
  values: scope fields must satisfy the value contract (plain valid UTF-8
  binary, no NUL/C0/DEL, at most 120 characters after trimming, blank being
  the intentional All choice) and the cursor must be a positive bigint, so
  invalid UTF-8, wrong types and non-positive cursors are silently dropped.
  Total: any other shape yields an empty map instead of raising.
  """
  @spec query_params(term()) :: map()
  def query_params(%{owner: owner, environment: environment, before_id: before_id}) do
    qs =
      %{owner: validated_scope(owner), environment: validated_scope(environment)}
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    case validated_cursor(before_id) do
      nil -> qs
      before -> Map.put(qs, :before, before)
    end
  end

  def query_params(_other), do: %{}

  # The scope value contract itself lives in `FindingFilters.scope_value/1`, so
  # the parse direction (URL params and filter events) and this emit direction
  # cannot disagree about what a valid scope value is. A value that fails the
  # contract is dropped here: this map only ever emits validated route params,
  # rather than emitting one and having it rejected on the way back in.
  defp validated_scope(value) do
    case FindingFilters.scope_value(value) do
      {:ok, trimmed} -> trimmed
      {:error, _reason} -> nil
    end
  end

  # The cursor is emitted only as a plain positive bigint within int8 bounds.
  defp validated_cursor(value) when is_integer(value) and value > 0 and value <= @cursor_max,
    do: Integer.to_string(value)

  defp validated_cursor(_other), do: nil

  # The cursor: absent, nil or empty means newest; anything else must be a
  # plain binary of 1-19 ASCII decimal digits within positive bigint bounds.
  # No coercion of integers, floats, lists or maps; no sign, whitespace or
  # oversized text is tolerated.
  defp cursor_value(nil), do: {:ok, nil}
  defp cursor_value(""), do: {:ok, nil}

  defp cursor_value(value) when is_binary(value) do
    cond do
      not String.valid?(value) ->
        {:error, :before}

      not Regex.match?(@cursor_digits, value) ->
        {:error, :before}

      true ->
        case Integer.parse(value) do
          {n, ""} when n > 0 and n <= @cursor_max -> {:ok, n}
          _other -> {:error, :before}
        end
    end
  end

  defp cursor_value(_other), do: {:error, :before}

  # A wrapper event submitted through the real filter form also serializes
  # the form's own fields alongside the wrapper: empty selects are the
  # neutral All state and carry no second, conflicting filter intent. Any
  # real, invalid or nonblank cursor value next to a wrapper is ambiguous
  # and rejected; unrelated metadata such as `"_target"` is never taken.
  defp blank_flat_fields?(flat) when flat == %{}, do: true

  defp blank_flat_fields?(flat) do
    flat
    |> Enum.all?(fn {_key, value} -> blank_value?(value) end)
  end

  defp blank_value?(nil), do: true

  defp blank_value?(value) when is_binary(value) do
    String.valid?(value) and not Regex.match?(@unsafe_text, value) and String.trim(value) == ""
  end

  defp blank_value?(_other), do: false

  defp mark_invalid(acc, field), do: %{acc | invalid: [field | acc.invalid]}
end
