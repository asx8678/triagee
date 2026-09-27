defmodule Triage.CollectionFixture do
  @moduledoc """
  Loads a raw collection fixture and normalizes it.

  Requested owners, environment and engine always come from
  `Triage.Collection.FixtureContract`. The JSON file cannot set them, and it
  cannot set `in_scope`.
  """

  alias Triage.Collection.{Config, FixtureContract, Normalize}

  def report!(name, opts \\ []) do
    Normalize.build(context!(name, opts))
  end

  def context!(name, opts \\ []) do
    raw = Jason.decode!(File.read!(path(name)))
    {:ok, config} = Config.new(config_opts(opts))

    images = Map.get(raw, "images", [])

    %{
      config: config,
      scope: "fixture",
      status_marker: Map.get(raw, "status_marker"),
      owners: FixtureContract.owners(),
      requested_owners: FixtureContract.owners(),
      warnings: [],
      failures: [],
      requests: 0,
      duration_ms: 0,
      inventory: Map.new(images, &inventory_entry/1),
      details: details(images)
    }
  end

  defp path(name) do
    Path.expand("../fixtures/experiment/collection/#{name}.json", __DIR__)
  end

  defp config_opts(opts) do
    [
      endpoint: "http://127.0.0.1",
      environment: FixtureContract.environment(),
      engine: FixtureContract.engine(),
      max_records: Keyword.get(opts, :max_records, 50_000)
    ]
  end

  defp inventory_entry(image) do
    digest = image["digest"]
    placements = placements(image)
    open = image["open"] || []
    suppressed = image["suppressed"] || []

    {digest,
     %{
       digest: digest,
       owners: MapSet.new(Enum.map(placements, & &1.owner)),
       api_ids: MapSet.new([image["api_id"]]),
       placements: MapSet.new(placements),
       image: %{
         "metrics" => %{
           "vulnerabilities" => length(open) + length(suppressed),
           "vulnerabilitiesSuppressed" => length(suppressed)
         }
       }
     }}
  end

  defp details(images) do
    images
    |> Enum.reject(& &1["omit_detail"])
    |> Map.new(fn image ->
      open = image["open"] || []
      suppressed = image["suppressed"] || []

      {image["digest"],
       %{
         "metrics" => %{
           "vulnerabilities" => length(open) + length(suppressed),
           "vulnerabilitiesSuppressed" => length(suppressed)
         },
         "vulnerabilities" => open,
         "excludedVulnerabilities" => suppressed
       }}
    end)
  end

  defp placements(%{"placements" => placements}) when is_list(placements) do
    Enum.map(placements, fn placement ->
      %{owner: placement["owner"], namespace: placement["namespace"]}
    end)
  end

  defp placements(image) do
    [%{owner: image["owner"], namespace: image["namespace"]}]
  end
end
