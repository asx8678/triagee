defmodule Triage.Intel.Sanitize do
  @moduledoc """
  Untrusted-text normalization for intelligence data.

  Mirrors the safety discipline of `TriageWeb.FindingFilters`: control
  characters and invalid UTF-8 are never silently trimmed away — we strip
  them deterministically, bound length, and render the result as TEXT only.
  No HTML is passed through; links are validated separately as https-only.
  """

  @max_text 2_000
  @title_max 300
  @cve_regex ~r/\ACVE-\d{4}-\d{4,}\z/i

  @doc """
  Reduce external text to safe plain text.

  Returns `nil` for nil/empty, else a trimmed, control-character-stripped
  string bounded to the given max. Never raises on hostile input.
  """
  def text(value, max \\ @max_text)

  def text(nil, _max), do: nil

  def text(value, max) when is_binary(value) do
    case String.valid?(value) do
      false ->
        nil

      true ->
        value
        |> String.replace(~r/[\x00-\x1F\x7F]/u, " ")
        |> String.replace(~r/\s+/u, " ")
        |> String.trim()
        |> case do
          "" -> nil
          s -> String.slice(s, 0, min(max, @max_text))
        end
    end
  end

  def text(_other, _max), do: nil

  def title(value), do: text(value, @title_max)

  @doc "Strict allowlist for an advisories' external id: canonical CVE format only."
  def valid_cve_id?(id) when is_binary(id) do
    # Raw match only — trailing/leading whitespace or control characters are
    # rejected, mirroring FindingFilters' no-silent-trim rule.
    String.match?(id, @cve_regex) and id == String.upcase(id)
  end

  def valid_cve_id?(_), do: false

  @doc "Uppercase-normalize a validated CVE id; nil for invalid."
  def normalize_cve_id(id) when is_binary(id) do
    if valid_cve_id?(id), do: String.upcase(String.trim(id)), else: nil
  end

  def normalize_cve_id(_), do: nil
end
