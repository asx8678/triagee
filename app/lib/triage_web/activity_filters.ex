defmodule TriageWeb.ActivityFilters do
  @moduledoc """
  Parameter contract for the read-only What's New lifecycle feed: the
  optional `owner`/`environment` scope and the `before` keyset cursor.

  This module intentionally delegates the whole safety contract to
  `TriageWeb.CaseFilters`: What's New has exactly the same three recognized
  fields and the same rules (raw valid UTF-8 with no NUL/C0/DEL before
  trimming, at most 120 characters after trimming, blank meaning the
  intentional All choice; absent/nil/empty `before` meaning newest, otherwise
  1-19 ASCII digits representing a positive int8 bigint). Reusing the
  existing validator keeps the two feeds from drifting apart instead of
  copying the boundary logic a second time.

  The returned map has the same shape as `CaseFilters`: plain atom-keyed
  `%{owner:, environment:, before_id:, invalid:}` where `invalid` is a list
  of recognized fields. Scope filters are display scoping, never
  authorization, and invalid recognized input never loads a widened view.
  """

  alias TriageWeb.CaseFilters

  @doc "The intentional All/newest state: no scope restrictions, no cursor."
  defdelegate defaults(), to: CaseFilters

  @doc """
  Parses raw string-keyed URL params through the shared contract. The
  reserved `"filters"` wrapper key is invalid in URL parsing; genuinely
  unrelated metadata is ignored.
  """
  defdelegate parse(params), to: CaseFilters

  @doc """
  Parses a `filter` event through the shared contract: exactly one plain
  `"filters"` wrapper level is supported, struct bodies (including outer
  structs carrying a `"filters"` key) are rejected, and unrelated event
  metadata is ignored.
  """
  defdelegate parse_event(params), to: CaseFilters

  @doc """
  Emits atom-keyed, validated query params for verified routes: only non-nil
  validated scope values and a stringified positive-bigint cursor survive.
  """
  defdelegate query_params(parsed), to: CaseFilters
end
