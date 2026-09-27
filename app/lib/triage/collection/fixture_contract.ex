defmodule Triage.Collection.FixtureContract do
  @moduledoc """
  Server-side scope for offline fixture ingestion.

  These values are not a G01 live-source approval and are not read from a
  collection payload. A report cannot authorize itself by setting `in_scope`.
  """

  @source "fixture-collection"
  @environment "fixture"
  @engine "Grype"
  @owner "fixture-owner"
  @image_id "11111111-1111-4111-8111-111111111111"
  @query_version "collection-fixture-v1"
  @paging_contract "none"

  def source, do: @source
  def environment, do: @environment
  def engine, do: @engine
  def owner, do: @owner
  def owners, do: [@owner]
  def image_id, do: @image_id
  def query_version, do: @query_version
  def paging_contract, do: @paging_contract
end
