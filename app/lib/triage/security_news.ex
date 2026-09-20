defmodule Triage.SecurityNews do
  @moduledoc "On-demand public vulnerability and news feeds, independent of local inventory."
  alias Triage.Intel.Sanitize
  require Logger
  @nvd "https://services.nvd.nist.gov/rest/json/cves/2.0"
  @feed "https://www.bleepingcomputer.com/feed/"

  def critical(now \\ DateTime.utc_now()) do
    start = now |> DateTime.to_date() |> Date.beginning_of_month() |> Date.to_iso8601()

    common = %{
      "pubStartDate" => start <> "T00:00:00.000",
      "pubEndDate" => Calendar.strftime(now, "%Y-%m-%dT%H:%M:%S.999"),
      "resultsPerPage" => "2000"
    }

    results =
      Enum.map(["cvssV3Severity", "cvssV4Severity"], fn key ->
        with {:ok, body} <-
               request(@nvd <> "?" <> URI.encode_query(Map.put(common, key, "CRITICAL"))),
             {:ok, decoded} <- Jason.decode(body) do
          parse_cves(decoded)
        end
      end)

    case results do
      [{:ok, left}, {:ok, right}] ->
        {:ok,
         %{
           rows:
             Enum.uniq_by(left.rows ++ right.rows, & &1.id) |> Enum.sort_by(& &1.published, :desc),
           limited: left.limited or right.limited,
           fetched_at: now
         }}

      _ ->
        {:error,
         "NVD could not be refreshed. It may be busy or rate limiting requests. Try again shortly."}
    end
  end

  def headlines do
    with {:ok, body} <- request(@feed), do: parse_headlines(body)
  end

  def parse_cves(%{"vulnerabilities" => entries, "totalResults" => total})
      when is_list(entries) and is_integer(total) do
    rows = Enum.flat_map(entries, &critical_row/1)

    {:ok, %{rows: rows, limited: total > length(entries)}}
  end

  def parse_cves(_), do: {:error, :invalid_nvd_response}

  defp critical_row(%{"cve" => %{"id" => id} = cve}) do
    metrics = cve |> Map.get("metrics", %{}) |> Map.values() |> List.flatten()

    scores =
      for %{"cvssData" => %{"baseScore" => score}} <- metrics,
          is_number(score),
          score >= 9,
          do: score

    if Sanitize.valid_cve_id?(id) and cve["vulnStatus"] != "Rejected" and scores != [],
      do: [cve_row(cve, Enum.max(scores))],
      else: []
  end

  defp critical_row(_), do: []

  defp cve_row(cve, score) do
    descriptions = Map.get(cve, "descriptions", [])
    description = Enum.find(descriptions, %{}, &(&1["lang"] == "en"))["value"] |> Sanitize.text()
    products = cve |> Map.get("configurations", []) |> products() |> Enum.uniq() |> Enum.sort()
    references = Enum.map(Map.get(cve, "references", []), &Map.get(&1, "url", ""))

    ecosystems =
      for {host, label} <- [
            {"pypi.org", "Python / PyPI"},
            {"npmjs.com", "JavaScript / npm"},
            {"rubygems.org", "Ruby"},
            {"crates.io", "Rust"},
            {"pkg.go.dev", "Go"},
            {"nuget.org", ".NET"},
            {"packagist.org", "PHP"},
            {"maven.org", "Java / Maven"}
          ],
          Enum.any?(references, &host?(&1, host)),
          do: label

    %{
      id: cve["id"],
      description: description || "No English description published.",
      score: score,
      published: String.slice(cve["published"] || "", 0, 10),
      products: Enum.join(products, ", "),
      ecosystems: Enum.join(ecosystems, ", ")
    }
  end

  defp products(value) when is_list(value), do: Enum.flat_map(value, &products/1)

  defp products(%{"criteria" => cpe, "vulnerable" => true}) when is_binary(cpe) do
    case String.split(cpe, ":") do
      ["cpe", "2.3", _, vendor, product | _] ->
        [String.replace(vendor <> " / " <> product, "_", " ")]

      _ ->
        []
    end
  end

  defp products(value) when is_map(value), do: value |> Map.values() |> Enum.flat_map(&products/1)
  defp products(_), do: []

  def parse_headlines(body) when is_binary(body) do
    case :xmerl_sax_parser.stream(body, [
           :skip_external_dtd,
           :disallow_entities,
           {:event_fun, &rss_event/3},
           {:event_state, %{items: [], item: nil, field: nil}}
         ]) do
      {:ok, state, _} ->
        items =
          state.items
          |> Enum.reverse()
          |> Enum.filter(fn item ->
            host?(item["link"] || "", "bleepingcomputer.com") and
              Regex.match?(
                ~r/CVE-|vulnerabil|zero.day|flaw|exploit|patch|critical/i,
                item["title"] || ""
              )
          end)
          |> Enum.take(20)
          |> Enum.map(fn item ->
            %{
              title: Sanitize.text(item["title"], 300),
              url: String.trim(item["link"]),
              date: Sanitize.text(item["pubDate"])
            }
          end)

        {:ok, %{items: items, fetched_at: DateTime.utc_now()}}

      error ->
        Logger.warning(
          "Vulnerability RSS parse failed: #{inspect(error, limit: 3, printable_limit: 120)}"
        )

        {:error, "News feed could not be read. Please try again."}
    end
  rescue
    error ->
      Logger.warning("Vulnerability RSS parser failed: #{Exception.message(error)}")
      {:error, "News feed could not be read. Please try again."}
  end

  defp rss_event({:startElement, _, ~c"item", _, _}, _, state),
    do: %{state | item: %{}, field: nil}

  defp rss_event({:startElement, _, name, _, _}, _, %{item: item} = state) when is_map(item) do
    field = List.to_string(name)
    %{state | field: if(field in ["title", "link", "pubDate"], do: field)}
  end

  defp rss_event({:characters, chars}, _, %{item: item, field: field} = state)
       when is_map(item) and is_binary(field),
       do: %{
         state
         | item: Map.update(item, field, List.to_string(chars), &(&1 <> List.to_string(chars)))
       }

  defp rss_event({:endElement, _, ~c"item", _}, _, state),
    do: %{state | items: [state.item | state.items], item: nil, field: nil}

  defp rss_event({:endElement, _, _, _}, _, state), do: %{state | field: nil}
  defp rss_event(_, _, state), do: state

  defp host?(url, host) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: "https", host: name} when is_binary(name) ->
        name == host or String.ends_with?(name, "." <> host)

      _ ->
        false
    end
  end

  defp request(url) do
    transport = Application.get_env(:triage, :security_news_transport, &Req.get/2)

    case transport.(url, Triage.HTTP.options(timeout: 25_000, max_bytes: 16_000_000)) do
      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        Triage.HTTP.bounded_body(body, 16_000_000)

      _ ->
        {:error, "Source is unavailable. Please try again shortly."}
    end
  rescue
    _ -> {:error, "Source is unavailable. Please try again shortly."}
  end
end
