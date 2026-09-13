defmodule TriageWeb.FindingFilters do
  @moduledoc """
  Shared, explicit validation and normalization contract for the finding list
  and detail scope parameters: `owner`, `environment`, `q`, `suppressed`,
  `severity`, plus the list-only `sort` order and its `before` keyset position.

  Scope filters are display scoping, never authorization. A value is accepted
  only when it is a plain binary that is valid UTF-8 with no NUL or other
  control characters *on the raw value, before trimming*, and of at most 120
  characters after trimming; space-only blank values are the intentional All
  choice. Anything else — maps, lists, other types, oversized or unsafe text,
  including control characters that trimming would remove — is reported in
  `:invalid` so callers render a visible invalid-filter state with no data
  instead of coercing the value with `to_string`, truncating it into another
  owner's name, silently unscoping or letting it crash against PostgreSQL.

  A `filter` event is normally a flat form; a nested `filters` map wrapper is
  supported but validated explicitly with the same contract.
  """

  @max_length 120
  @recognized ~w(owner environment q suppressed severity sort before)

  # Every recognized field except `before`, which cannot be validated on its
  # own: a position only means something in one result order, so it is checked
  # once the order is known.
  @independent ~w(owner environment q suppressed severity sort)
  @suppressed_truthy ~w(1 true on)
  @suppressed_falsy ~w(0 false)
  @severities ~w(CRITICAL HIGH MEDIUM LOW)
  @unsafe_text ~r/[\x00-\x1F\x7F]/

  alias Triage.Inventory.GroupCursor

  @doc """
  The intentional All choice: no scope restrictions, the default result order
  (`:sort` nil means `severity`) and the start of that order (`:before` nil
  means the newest slice).
  """
  def defaults do
    %{
      owner: nil,
      environment: nil,
      q: nil,
      include_suppressed: false,
      severity: nil,
      sort: nil,
      before: nil,
      invalid: []
    }
  end

  @doc "Result orders accepted by `parse/1`, i.e. `Triage.Inventory.group_sorts/0`."
  def sorts, do: Triage.Inventory.group_sorts()

  @doc """
  Parses raw string-keyed params (query strings or flat form events). Only
  recognized fields are considered; genuinely unrelated query or form
  metadata is ignored safely. The reserved `"filters"` wrapper key is never
  accepted here: its presence means an ambiguous or nested wrapper that must
  be rejected, not ignored as harmless metadata.
  """
  def parse(params) when is_map(params) do
    if Map.has_key?(params, "filters") do
      mark_invalid(defaults(), :filters)
    else
      params
      |> Map.take(@independent)
      |> Enum.reduce(defaults(), fn {field, value}, acc ->
        field = String.to_existing_atom(field)
        {status, normalized} = field_value(field, value)

        key = if field == :suppressed, do: :include_suppressed, else: field

        acc
        |> Map.put(key, normalized)
        |> then(fn acc -> if status == :error, do: mark_invalid(acc, field), else: acc end)
      end)
      |> parse_cursor(Map.get(params, "before"))
    end
  end

  # Total public boundary: any other incoming term (nil, numbers, lists,
  # booleans, ...) surfaces the invalid state instead of raising and killing
  # the LiveView channel.
  def parse(_other), do: mark_invalid(defaults(), :filters)

  # A position is only a position in one order, so the cursor is validated
  # against the order this parse resolved — the default order when the request
  # named none. A position issued for a different order is not a position here,
  # and a malformed or non-canonical one is a visible invalid filter rather
  # than a silently different slice of the list.
  defp parse_cursor(acc, value) do
    case GroupCursor.parse(acc.sort || Triage.Inventory.default_group_sort(), value) do
      {:ok, before} -> %{acc | before: before}
      {:error, :before} -> mark_invalid(acc, :before)
    end
  end

  @doc """
  Parses a `filter` event. Exactly one `"filters"` wrapper level is supported:
  a legitimate wrapper event is unwrapped once and validated with the
  URL-param contract. Rejected instead of silently unwrapped or ignored: a
  non-map wrapper, a doubly nested `"filters"` key (reserved; `parse/1`
  rejects it) and ambiguous combinations where a wrapper appears alongside
  recognized flat fields carrying real values. Non-map event bodies surface
  the invalid state instead of raising and killing the LiveView.
  """
  def parse_event(%{"filters" => filters} = params) when is_map(filters) do
    if blank_flat_fields?(Map.take(params, @recognized)) do
      parse(filters)
    else
      mark_invalid(defaults(), :filters)
    end
  end

  def parse_event(%{"filters" => _other}), do: mark_invalid(defaults(), :filters)
  def parse_event(params) when is_map(params), do: parse(params)
  def parse_event(_other), do: mark_invalid(defaults(), :filters)

  # A wrapper event submitted through the real filter form also serializes
  # the form's own fields alongside the wrapper: empty selects and text
  # inputs plus an unchecked checkbox are the neutral All state and carry no
  # second, conflicting filter intent. Any real or invalid flat value next
  # to a wrapper is ambiguous and rejected; unrelated metadata such as
  # `"_target"` never reaches this check.
  defp blank_flat_fields?(flat) when flat == %{}, do: true

  defp blank_flat_fields?(flat) do
    parsed = parse(flat)

    parsed.invalid == [] and parsed.owner == nil and parsed.environment == nil and
      parsed.q == nil and parsed.include_suppressed == false and neutral_order?(parsed)
  end

  # The real filter form serializes its order control on every event, so a flat
  # value that equals the default order — and no position at all, because the
  # form has no cursor field — carries no second filter intent next to a
  # wrapper. Any other value there is a genuine conflict and stays rejected as
  # ambiguous.
  defp neutral_order?(parsed) do
    parsed.sort in [nil, Triage.Inventory.default_group_sort()] and parsed.before == nil
  end

  @doc """
  Atom-keyed query params for verified routes, dropping blank All choices and
  encoding `suppressed` as `\"1\"`. Built from validated values only.
  """
  def query_params(
        %{owner: owner, environment: environment, q: q, include_suppressed: s} = parsed
      ) do
    qs =
      %{
        owner: owner,
        environment: environment,
        q: q,
        severity: Map.get(parsed, :severity),
        sort: Map.get(parsed, :sort),
        before: encode_cursor(parsed)
      }
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    if s, do: Map.put(qs, :suppressed, "1"), else: qs
  end

  # A position is emitted re-encoded from its parsed fields, so a route this
  # module builds can only ever carry a cursor this module accepted.
  defp encode_cursor(parsed) do
    sort = Map.get(parsed, :sort) || Triage.Inventory.default_group_sort()

    case Map.get(parsed, :before) do
      nil -> nil
      before -> GroupCursor.encode(sort, before)
    end
  end

  defp field_value(:severity, nil), do: {:ok, nil}

  defp field_value(:severity, value) when is_binary(value) do
    cond do
      not String.valid?(value) ->
        {:error, nil}

      Regex.match?(@unsafe_text, value) ->
        {:error, nil}

      true ->
        case String.trim(value) do
          "" ->
            {:ok, nil}

          trimmed ->
            normalized = String.upcase(trimmed)

            if normalized in @severities do
              {:ok, normalized}
            else
              {:error, nil}
            end
        end
    end
  end

  defp field_value(:severity, _other), do: {:error, nil}

  defp field_value(:sort, nil), do: {:ok, nil}

  defp field_value(:sort, value) when is_binary(value) do
    cond do
      not String.valid?(value) ->
        {:error, nil}

      Regex.match?(@unsafe_text, value) ->
        {:error, nil}

      true ->
        case value |> String.trim() |> String.downcase() do
          "" ->
            {:ok, nil}

          normalized ->
            if normalized in Triage.Inventory.group_sorts(),
              do: {:ok, normalized},
              else: {:error, nil}
        end
    end
  end

  defp field_value(:sort, _other), do: {:error, nil}

  defp field_value(:suppressed, nil), do: {:ok, false}

  defp field_value(:suppressed, value) when is_binary(value) do
    # Raw validation first: control characters or invalid UTF-8 are rejected
    # even when trimming would remove them.
    cond do
      not String.valid?(value) ->
        {:error, false}

      Regex.match?(@unsafe_text, value) ->
        {:error, false}

      true ->
        case String.trim(value) do
          "" -> {:ok, false}
          trimmed when trimmed in @suppressed_truthy -> {:ok, true}
          trimmed when trimmed in @suppressed_falsy -> {:ok, false}
          _other -> {:error, false}
        end
    end
  end

  defp field_value(:suppressed, _other), do: {:error, false}

  # `owner`/`environment` — and any field without a specialized clause above —
  # use the published scope value contract defined below.
  defp field_value(_scope, value), do: scope_value(value)

  @doc "
  The scope value contract, published because more than one caller implements it.

  Accepts a plain binary that is valid UTF-8 with no NUL or other control
  character *before* trimming and at most #{@max_length} characters after
  trimming. Blank or space-only is the intentional All choice.

  Returns `{:ok, nil | trimmed}` for an accepted value, including the blank All
  choice, and `{:error, nil}` for anything that must surface as a visible
  invalid filter: wrong types, invalid UTF-8, control characters, or text that
  is too long. `TriageWeb.CaseFilters` calls this instead of restating the
  contract when it emits route params, so the parse and emit directions cannot
  silently disagree about what a valid scope value is.
  "
  def scope_value(nil), do: {:ok, nil}

  def scope_value(value) when is_binary(value) do
    # Raw validation first: control characters or invalid UTF-8 are rejected
    # even when trimming would remove them. Only then do ordinary blank or
    # space-only values keep the intentional All semantics.
    cond do
      not String.valid?(value) ->
        {:error, nil}

      Regex.match?(@unsafe_text, value) ->
        {:error, nil}

      true ->
        trimmed = String.trim(value)

        cond do
          trimmed == "" -> {:ok, nil}
          String.length(trimmed) > @max_length -> {:error, nil}
          true -> {:ok, trimmed}
        end
    end
  end

  def scope_value(_other), do: {:error, nil}

  defp mark_invalid(acc, field), do: %{acc | invalid: [field | acc.invalid]}
end
