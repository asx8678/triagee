defmodule Mix.Tasks.Triage.Intel do
  @moduledoc """
  Manual public-intelligence refresh. Writes only the intel cache and receipts;
  never touches findings, placements, cases, reviews, or any endpoint.

  Requires prior approval plus, at minimum:

      config :triage, :intel,
        enabled: true,
        sources: [:kev]  # one or more of :kev | :nvd

  All requests are HTTPS allowlisted, redirect-refused, byte- and time-bounded,
  and text is sanitized before cache. A failed refresh preserves the last good
  cache and records a failed receipt.

      mix triage.intel --kev
      mix triage.intel --nvd CVE-2024-3094
      mix triage.intel --receipts
      mix triage.intel --kev --receipts
  """

  use Mix.Task
  alias Triage.Intel
  alias Triage.Intel.Client

  @shortdoc "Manual public vuln-intelligence refresh (KEV / NVD)"

  @impl true
  def run(args) do
    {opts, _rest, _invalid} =
      OptionParser.parse(args, strict: [kev: :boolean, nvd: :string, receipts: :boolean])

    # Compile loads code paths only. Load runtime config, start the Repo supervisor
    # ourselves — never the Endpoint, matching triage.replay and avoiding side effects.
    Mix.Task.run("compile", ["--quiet"])
    Mix.Task.run("app.config")

    {:ok, _} = Application.ensure_all_started(:logger)
    # The Repo needs its own applications started first: starting it alone fails with
    # "no process ... DBConnection.Watcher", which made every invocation of this task
    # crash. The Endpoint is still never started.
    {:ok, _} = Application.ensure_all_started(:ecto_sql)
    {:ok, _} = Application.ensure_all_started(:postgrex)
    {:ok, _} = Triage.Repo.start_link()

    Mix.shell().info("triage.intel — public intelligence refresh")
    Mix.shell().info("  enabled: #{Intel.Config.enabled?()}")
    Mix.shell().info("  sources: #{inspect(Intel.Config.enabled_sources())}")

    cond do
      # Reading receipts makes no request, so it stays available while disabled.
      not Intel.Config.enabled?() and not Keyword.get(opts, :receipts, false) ->
        Mix.shell().error(
          "  intel is disabled (set :triage, :intel, enabled: true, sources: [...])"
        )

        Mix.raise("intel disabled", exit_status: 1)

      not Enum.any?(opts, &elem(&1, 1)) ->
        Mix.shell().error("  nothing to do (use --kev, --nvd CVE-XXXX-YYYY, or --receipts)")
        Mix.raise("nothing to do", exit_status: 1)

      true ->
        :ok
    end

    failures = 0

    failures =
      if Keyword.get(opts, :kev, false) do
        refresh(:kev) + failures
      else
        failures
      end

    failures =
      case Keyword.get(opts, :nvd) do
        nil -> failures
        "" -> failures + 1
        cve_id -> refresh({:nvd, cve_id}) + failures
      end

    if Keyword.get(opts, :receipts, false) do
      print_receipts()
    end

    if failures > 0 do
      Mix.raise("#{failures} source(s) failed — last good cache preserved", exit_status: 2)
    end
  end

  defp refresh(request) do
    {kind, source, label} = source_details(request)

    if Intel.Config.source_allowed?(kind) do
      # app.config loads dependencies; it does not start Req's Finch supervisor.
      {:ok, _} = Application.ensure_all_started(:req)

      case Client.fetch(request) do
        {:ok, rows} ->
          {:ok, count} = Intel.replace_advisories(source, rows)
          {:ok, _} = Intel.record_receipt(source, true, count)
          suffix = if kind == :kev, do: " (#{length(rows)} rows)", else: ""
          Mix.shell().info("  #{label}: #{count} advisories cached#{suffix}")
          0

        {:error, reason} ->
          message = safe_error(reason)
          {:ok, _} = Intel.record_receipt(source, false, nil, message)
          Mix.shell().error("  #{label}: FAILED — #{message}")
          1
      end
    else
      # No request or receipt for an unapproved source.
      Mix.shell().error(
        "  #{kind}: not allowed — add it to :triage, :intel, sources: [...] to approve it"
      )

      1
    end
  end

  defp source_details(:kev), do: {:kev, "kev", "kev"}

  defp source_details({:nvd, cve_id}),
    do: {:nvd, Intel.nvd_source(cve_id), "nvd(#{cve_id})"}

  defp print_receipts do
    Mix.shell().info("Receipts:")

    receipts = Intel.latest_receipts()

    for receipt <- receipts do
      status = if receipt.succeeded, do: "ok    ", else: "FAILED"
      note = if(receipt.message, do: " — " <> receipt.message, else: "")
      Mix.shell().info("  #{receipt.source}: #{status} #{receipt.attempted_at}#{note}")
    end

    if receipts == [], do: Mix.shell().info("  (no receipts yet)")
  end

  defp safe_error(:kev_parse_failed), do: "KEV payload parse failed"
  defp safe_error(:nvd_parse_failed), do: "NVD payload parse failed"
  defp safe_error(:json_decode_failed), do: "invalid JSON"
  defp safe_error(:intel_disabled), do: "disabled by config"
  defp safe_error(:no_transport), do: "no transport configured"
  defp safe_error(:request_raised), do: "request crashed safely"
  defp safe_error({:invalid_cve_id, _}), do: "invalid CVE id"
  defp safe_error({:request_failed, _reason}), do: "request failed"
  defp safe_error({:redirect_refused, status}), do: "redirect #{status} refused"
  defp safe_error({:http_status, status}), do: "HTTP #{status}"
  defp safe_error({:response_too_large, max}), do: "response exceeded #{max} bytes"
  defp safe_error({:unallowlisted_url, host}), do: "host not allowlisted: #{host || "(unknown)"}"
  defp safe_error(other) when is_binary(other), do: String.slice(other, 0, 80)
  defp safe_error(_other), do: "unknown error"
end
