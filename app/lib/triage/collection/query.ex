defmodule Triage.Collection.Query do
  @moduledoc """
  GraphQL query builders with validated interpolation.

  The source endpoint does not reliably support variables, so arguments are
  interpolated after strict validation and JSON escaping: a hostile owner or id
  string cannot break out of a GraphQL string literal.

  Public validators (`valid_image_id?/1`, `valid_identifier?/1`) let callers
  reject malformed source identifiers BEFORE interpolating, so an untrusted
  upstream value cannot raise inside a linked worker.
  """

  @uuid_re ~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
  @unsafe ~r/["\\\x00-\x1F\x7F]/

  @status "{ status { lastClusterScan } }"
  @owners "{ owner { id } }"

  @doc "Observational cluster-scan marker query. Never a freshness or cursor claim."
  def status_query, do: @status

  @doc "Owner inventory query."
  def owners_query, do: @owners

  @doc "True when a source image id is a syntactically valid UUID."
  def valid_image_id?(value) when is_binary(value), do: Regex.match?(@uuid_re, value)
  def valid_image_id?(_other), do: false

  @doc "True when an identifier is safe to interpolate into a string literal."
  def valid_identifier?(value) when is_binary(value) do
    value != "" and String.length(value) <= 128 and not Regex.match?(@unsafe, value)
  end

  def valid_identifier?(_other), do: false

  @doc "Stage one: the image inventory for one owner (no vulnerabilities requested)."
  def image_list_query(owner) do
    """
    {
      image(owner: #{ident(owner)}) {
        id
        digest
        description
        repository
        tag
        usage
        softwareBillOfMaterialCreatedBy
        usedInNamespaces { id owner }
        metrics {
          status
          vulnerabilities
          vulnerabilitiesSuppressed
        }
      }
    }
    """
  end

  @doc "Stage two: findings for one image id. `engine` is mandatory in practice."
  def image_detail_query(image_id, engine) do
    """
    {
      image(id: #{uuid(image_id)}, engine: #{ident(engine)}) {
        id
        digest
        description
        tag
        softwareBillOfMaterialCreatedBy
        metrics { status vulnerabilities vulnerableComponents }
        vulnerabilities {
          vuln severity baseSeverity source
          packageName packageVersion packageType packagePath packageCpe
          fix url description attributedOn
        }
        excludedVulnerabilities {
          vuln severity baseSeverity source
          packageName packageVersion packageType packagePath packageCpe
          fix url description attributedOn
        }
      }
    }
    """
  end

  defp ident(value) when is_binary(value) do
    if value == "" or String.length(value) > 128 or Regex.match?(@unsafe, value) do
      raise ArgumentError, "refusing to interpolate unsafe identifier"
    end

    Jason.encode!(value)
  end

  defp ident(_other), do: raise(ArgumentError, "identifier must be a string")

  defp uuid(value) do
    if not is_binary(value) or not Regex.match?(@uuid_re, value) do
      raise ArgumentError, "not a valid image id (uuid)"
    end

    Jason.encode!(value)
  end
end
