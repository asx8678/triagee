defmodule Triage.Reporting do
  @moduledoc "Versioned, read-only current-state projection for authorized reporting clients."

  alias Triage.Reporting.{Cursor, Filters, Query}

  @schema_version "1.0"

  def fetch(kind, params, access, now \\ DateTime.utc_now()) do
    now = DateTime.truncate(now, :second)

    with {:ok, filters} <- Filters.validate(kind, params),
         :ok <- authorize_scope(access, filters),
         {:ok, position} <- Cursor.decode(filters.cursor, kind, filters, access) do
      Query.snapshot(fn -> run(kind, filters, access, now, position) end)
    end
  end

  defp run(:summary, filters, access, now, _position) do
    data = Query.summary(filters, access, now) |> severity_breakdown()
    {:ok, envelope(data, filters, now)}
  end

  defp run(:cves, filters, access, now, position) do
    result = Query.cves(filters, access, now, position)

    page(
      result["rows"],
      result["total"],
      filters,
      access,
      now,
      :cves,
      fn row ->
        row
        |> Map.update!("severity", &Triage.Severity.label/1)
        |> Map.update!("priority", &Triage.Severity.label/1)
        |> Map.update!("first_seen", &utc/1)
        |> Map.update!("last_seen", &utc/1)
        |> Map.put("detail_path", cve_path(row["cve"], filters))
      end,
      fn row -> %{"cve" => row["cve"]} end
    )
  end

  defp run(:targets, filters, access, now, position) do
    result = Query.target_keys(filters, access, now, position)
    {shown_keys, has_more?} = take_page(result["rows"], filters.limit)
    targets = Query.hydrate_targets(shown_keys, now)
    rows = Enum.map(targets, &target_json(&1, now))
    next_position = if has_more?, do: List.last(shown_keys), else: nil

    {:ok,
     envelope(rows, filters, now,
       total: result["total"],
       next_cursor: encode_next(:targets, filters, access, next_position)
     )}
  end

  defp run(:cve, filters, access, now, _position) do
    list_filters = %{filters | active: true, limit: 1, whitelist_coverage: ""}
    result = Query.cves(list_filters, access, now, nil)

    case result["rows"] do
      [row | _] ->
        row =
          row
          |> Map.update!("severity", &Triage.Severity.label/1)
          |> Map.update!("priority", &Triage.Severity.label/1)
          |> Map.update!("first_seen", &utc/1)
          |> Map.update!("last_seen", &utc/1)
          |> Map.put("detail_path", cve_path(row["cve"], filters))
          |> Map.put(
            "targets_path",
            query_path("/api/v1/targets", %{
              "active" => "true",
              "cve" => row["cve"],
              "team" => filters.team,
              "environment" => filters.environment
            })
          )

        {:ok, envelope(row, filters, now)}

      [] ->
        not_found()
    end
  end

  defp run(:packages, filters, access, now, position) do
    result = Query.packages(filters, access, position)

    if result["total"] == 0 do
      not_found()
    else
      page(
        result["rows"],
        result["total"],
        filters,
        access,
        now,
        :packages,
        fn row ->
          row
          |> Map.update!("id", &Integer.to_string/1)
          |> Map.update!("first_seen", &utc/1)
          |> Map.update!("last_seen", &utc/1)
          |> Map.update!("resolved_at", &utc/1)
        end,
        fn row -> %{"finding_id" => row["id"]} end
      )
    end
  end

  defp run(:options, filters, access, now, position) do
    rows = Query.options(filters, access, position)
    {shown, has_more?} = take_page(rows, filters.limit)
    next_position = if has_more?, do: List.last(shown), else: nil

    data = %{
      "pairs" => shown,
      "teams" => shown |> Enum.map(& &1["team"]) |> Enum.uniq(),
      "environments" => shown |> Enum.map(& &1["environment"]) |> Enum.uniq(),
      "severities" => Triage.Severity.order(),
      "whitelist_coverage" => ~w(none partial full not_applicable)
    }

    {:ok,
     envelope(data, filters, now,
       next_cursor: encode_next(:options, filters, access, next_position)
     )}
  end

  defp page(rows, total, filters, access, now, endpoint, mapper, position) do
    {shown, has_more?} = take_page(rows, filters.limit)
    mapped = Enum.map(shown, mapper)
    next_position = if has_more?, do: shown |> List.last() |> position.(), else: nil

    {:ok,
     envelope(mapped, filters, now,
       total: total,
       next_cursor: encode_next(endpoint, filters, access, next_position)
     )}
  end

  defp take_page(rows, limit), do: {Enum.take(rows, limit), length(rows) > limit}
  defp encode_next(_endpoint, _filters, _access, nil), do: nil

  defp encode_next(endpoint, filters, access, position),
    do: Cursor.encode(endpoint, filters, access, position)

  defp envelope(data, filters, now, opts \\ []) do
    response = %{
      "data" => data,
      "meta" => %{
        "schema_version" => @schema_version,
        "evaluated_at" => DateTime.to_iso8601(now),
        "consistency" => "per_response",
        "counting_units" => %{
          "cve" => "distinct CVE in the authorized requested scope",
          "target" => "one CVE on one placement"
        },
        "policy" => %{
          "attention_version" => Triage.Attention.version(),
          "risk_version" => Triage.Risk.policy_version(),
          "evidence_packet_version" => Triage.Evidence.packet_version(),
          "legacy_dismissal_policy" => Atom.to_string(Triage.Evidence.legacy_policy())
        },
        "filters" => public_filters(filters),
        "source_coverage" => "unknown",
        "limitations" => [
          "Current recorded inventory; not proof of complete live scanning.",
          "evaluated_at is not a source scan timestamp.",
          "Risk acceptance is not remediation."
        ]
      }
    }

    if Keyword.has_key?(opts, :total) or Keyword.has_key?(opts, :next_cursor) do
      Map.put(response, "pagination", %{
        "total" => Keyword.get(opts, :total),
        "next_cursor" => Keyword.get(opts, :next_cursor)
      })
    else
      response
    end
  end

  defp target_json(target, now) do
    decision = target.decision

    %{
      "cve" => target.cve,
      "placement_id" => Integer.to_string(target.id),
      "team" => Triage.Workspace.team_key(target.placement.owner),
      "environment" => target.placement.environment,
      "namespace" => target.placement.namespace,
      "image_digest" => target.image.digest,
      "image_repository" => target.image.repository,
      "image_tag" => target.image.tag,
      "severity" =>
        target.findings |> Enum.map(& &1.severity) |> Enum.max_by(&Triage.Severity.rank/1),
      "review_priority" => target.risk && target.risk.priority,
      "active" => target.active?,
      "exposure" => target.exposure,
      "exposure_state" => Atom.to_string(target.exposure_state),
      "decision_type" => decision && decision.decision,
      "decision_id" => decision && Integer.to_string(decision.id),
      "coverage_state" => Atom.to_string(target.coverage_state),
      "needs_decision" => target.needs_decision?,
      "needs_attention" => Triage.Attention.needs_attention?(target, now),
      "attention_reason" => Triage.Attention.reason(target, now),
      "whitelisted" =>
        (target.active? and target.covered? and decision) && decision.decision == "accepted_risk",
      "expires_at" => decision && datetime(decision.expires_at),
      "expiry_boundary" => decision && decision.metadata["expiry_boundary"],
      "first_observed_at" => datetime(target.first_seen),
      "last_observed_at" => datetime(target.last_seen),
      "package_count" =>
        target.findings |> Enum.map(& &1.package_name) |> Enum.uniq() |> length(),
      "detail_path" => target_path(target)
    }
  end

  defp target_path(target) do
    query = %{
      "page" => "review",
      "item" => target.cve,
      "team" => Triage.Workspace.team_key(target.placement.owner),
      "environment" => target.placement.environment,
      "focus_target" => Integer.to_string(target.id)
    }

    query_path("/", query) <> "#review-target-#{target.id}"
  end

  defp cve_path(cve, filters) do
    values = %{
      "page" => "review",
      "item" => cve,
      "team" => filters.team,
      "environment" => filters.environment
    }

    query_path("/", values)
  end

  defp query_path(path, values) do
    query =
      values
      |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)
      |> Map.new()
      |> URI.encode_query()

    if query == "", do: path, else: path <> "?" <> query
  end

  defp severity_breakdown(data) do
    Map.update!(data, "by_severity", fn rows ->
      Enum.map(rows, &Map.update!(&1, "severity", fn rank -> Triage.Severity.label(rank) end))
    end)
  end

  defp public_filters(filters) do
    filters
    |> Map.drop([:cursor, :cursor_position])
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)
    |> Map.new(fn {key, value} -> {Atom.to_string(key), value} end)
  end

  defp authorize_scope(%{grants: :all}, _filters), do: :ok

  defp authorize_scope(%{grants: grants}, filters) when is_list(grants) do
    allowed? =
      Enum.any?(grants, fn {team, environment} ->
        filters.team in ["", team] and filters.environment in ["", environment]
      end)

    if allowed?,
      do: :ok,
      else:
        {:error,
         %{
           status: 403,
           code: "forbidden_scope",
           detail: "Token does not grant the requested scope"
         }}
  end

  defp authorize_scope(_access, _filters),
    do: {:error, %{status: 403, code: "forbidden_scope", detail: "Token has no reporting scope"}}

  defp utc(nil), do: nil

  defp utc(value) when is_binary(value),
    do: if(String.ends_with?(value, "Z"), do: value, else: value <> "Z")

  defp datetime(nil), do: nil
  defp datetime(%DateTime{} = value), do: DateTime.to_iso8601(value)

  defp not_found,
    do:
      {:error,
       %{
         status: 404,
         code: "not_found",
         detail: "Record is not available in the authorized scope"
       }}
end
