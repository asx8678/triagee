defmodule Triage.Reporting do
  @moduledoc """
  Versioned, read-only projection for authorized reporting clients: current
  recorded state, plus the handling statistics the Statistics page shows.
  """

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

  # The Statistics page for the authorized scope: the same report, the same
  # whole-day rounding and the same outcome labels, so Grafana and the page
  # cannot disagree.
  defp run(:statistics, filters, access, now, _position) do
    report = statistics_report(filters, access, now)
    summary = report.summary
    handled_deployments = summary.outcomes |> Map.values() |> Enum.sum()

    data = %{
      "period" => filters.period,
      "since" => datetime(report.since),
      "open_cves" => summary.open,
      "oldest_open_days" => summary.oldest_open_days,
      "handled_cves" => summary.handled,
      "median_days_to_first_action" => whole_days(summary.median_days_to_first_action),
      "median_days_to_handle" => whole_days(summary.median_days_to_handle),
      "handled_deployments" => handled_deployments,
      "outcomes" =>
        summary.outcomes
        |> Enum.sort_by(fn {outcome, count} -> {-count, outcome} end)
        |> Enum.map(fn {outcome, count} ->
          %{
            "outcome" => outcome,
            "deployments" => count,
            "share_percent" => round(count * 100 / handled_deployments)
          }
        end)
    }

    {:ok, envelope(data, filters, now)}
  end

  defp run(:statistics_cves, filters, access, now, position) do
    report = statistics_report(filters, access, now)
    handled = MapSet.new(report.handled, & &1.cve)

    rows =
      case filters.status do
        "open" -> report.open
        "handled" -> report.handled
        _both -> Enum.uniq_by(report.open ++ report.handled, & &1.cve)
      end
      |> Enum.sort_by(& &1.cve)

    remaining =
      case position do
        %{"cve" => last} -> Enum.drop_while(rows, &(&1.cve <= last))
        _start -> rows
      end

    page(
      Enum.take(remaining, filters.limit + 1),
      length(rows),
      filters,
      access,
      now,
      :statistics_cves,
      &statistics_cve_json(&1, handled, filters),
      fn row -> %{"cve" => row.cve} end
    )
  end

  # A token limited to team and environment pairs sees only those deployments,
  # whatever the request filters are.
  defp statistics_report(filters, access, now) do
    %{"team" => filters.team, "environment" => filters.environment}
    |> Triage.Statistics.deployment_rows(now)
    |> Enum.filter(&granted?(access, &1))
    |> Triage.Statistics.report_from_rows(filters.period, now)
  end

  defp granted?(%{grants: :all}, _row), do: true

  defp granted?(%{grants: grants}, row) when is_list(grants),
    do: {Triage.Workspace.team_key(row.team), row.environment} in grants

  defp granted?(_access, _row), do: false

  defp statistics_cve_json(row, handled, filters) do
    action = row.first_action

    %{
      "cve" => row.cve,
      "severity" => row.severity,
      "packages" => Enum.join(row.packages, ", "),
      "deployments" => row.deployments,
      "open_deployments" => row.open_deployments,
      "status" => Atom.to_string(row.status),
      "handled_in_period" => MapSet.member?(handled, row.cve),
      "first_observed_at" => datetime(row.observed_at),
      "first_action" => action && action.label,
      "first_action_at" => action && datetime(action.at),
      "first_action_by" => action && action.by,
      "days_to_first_action" => row.days_to_first_action,
      "handled_at" => datetime(row.handled_at),
      "days_to_handle" => row.days_to_handle,
      "no_longer_observed_at" => datetime(row.gone_at),
      "days_open" => row.days_open,
      "outcome" => row.outcome,
      "current_state" => row.current_state,
      "detail_path" => cve_path(row.cve, filters)
    }
  end

  # Whole days, counted down, as the Statistics page and its CSV show them.
  defp whole_days(nil), do: nil
  defp whole_days(days), do: trunc(days)

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
