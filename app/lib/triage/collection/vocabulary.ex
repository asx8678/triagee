defmodule Triage.Collection.Vocabulary do
  @moduledoc """
  Exact fixture-query allowlist.

  A document is admitted only when it is byte-for-byte one of the fixture
  contract's `Triage.Collection.Query` documents. This is not a G01-approved
  live vocabulary and this module does not call a transport.
  """

  alias Triage.Collection.{FixtureContract, Query}

  @doc "Fixture query version. Not a live-contract version."
  def query_version, do: FixtureContract.query_version()

  @doc "The only documents this offline allowlist admits."
  def approved_documents do
    [
      Query.status_query(),
      Query.owners_query(),
      Query.image_list_query(FixtureContract.owner()),
      Query.image_detail_query(FixtureContract.image_id(), FixtureContract.engine())
    ]
  end

  @doc """
  Classifies one document. Mutation wording is a distinct denial; every other
  non-exact document is `:vocabulary_denied`.
  """
  def classify(document) when is_binary(document) do
    if document in approved_documents() do
      {:ok, :read}
    else
      {:error, deny_reason(document)}
    end
  end

  def classify(_other), do: {:error, :invalid_query}

  defp deny_reason(document) do
    if String.contains?(String.downcase(document), "mutation") do
      :mutation_denied
    else
      :vocabulary_denied
    end
  end
end
