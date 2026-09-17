defmodule Triage.ReviewIntegrations do
  @moduledoc "Explicitly configured, opt-in AI and Azure adapters for guided review."

  def config, do: Application.get_env(:triage, __MODULE__, [])

  def team_mapping(owner) when owner in [nil, "", "(unknown)", "unknown"], do: nil
  def team_mapping(owner) do
    case Map.get(Keyword.get(config(), :teams, %{}), owner) do
      %{"project" => project, "area_path" => area} = mapping
      when is_binary(project) and project != "" and is_binary(area) and area != "" -> mapping
      _ -> nil
    end
  end

  def azure_configured? do
    Enum.all?([:organization, :token], fn key ->
      value = Keyword.get(config(), key)
      is_binary(value) and String.trim(value) != ""
    end)
  end

  def ai_configured?, do: is_binary(Keyword.get(config(), :ai_executable))

  def create_ticket(plan) do
    adapter = Keyword.get(config(), :azure_adapter, __MODULE__.Azure)
    adapter.create(plan, config())
  rescue
    _ -> {:error, :unknown}
  catch
    _, _ -> {:error, :unknown}
  end

  def assess(input) do
    case Keyword.get(config(), :ai_executable) do
      executable when is_binary(executable) ->
        # An administrator-provided read-only wrapper, not a shell command.
        # Contract: one JSON argument in, one JSON object on stdout, no tools/actions.
        port = Port.open({:spawn_executable, executable}, [
          :binary, :exit_status, :use_stdio, :stderr_to_stdout,
          {:args, [Jason.encode!(input)]}
        ])
        deadline = System.monotonic_time(:millisecond) + 30_000
        collect(port, "", deadline)
      _ -> {:error, "Internal AI is not configured. A human can still make the decision."}
    end
  rescue
    _ -> {:error, "Internal AI could not be started. Check the configured read-only wrapper."}
  end

  defp collect(port, output, deadline) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))
    receive do
      {^port, {:data, data}} when byte_size(output) + byte_size(data) <= 65_536 ->
        collect(port, output <> data, deadline)
      {^port, {:data, _}} ->
        Port.close(port)
        {:error, "Internal AI output exceeded the limit."}
      {^port, {:exit_status, 0}} -> validate_advice(output)
      {^port, {:exit_status, _}} -> {:error, "Internal AI failed; no recommendation was accepted."}
    after
      remaining ->
        Port.close(port)
        {:error, "Internal AI timed out; no recommendation was accepted."}
    end
  end

  def validate_advice(output) do
    case Jason.decode(output) do
      {:ok, %{"recommendation" => recommendation, "reason" => reason}}
      when recommendation in ["whitelist", "fix", "investigate"] and is_binary(reason) and byte_size(reason) > 0 and byte_size(reason) <= 8000 ->
        {:ok, %{recommendation: recommendation, reason: reason}}
      _ -> {:error, "Internal AI returned an invalid recommendation."}
    end
  end

  defmodule Azure do
    def create(plan, config) do
      org = Keyword.fetch!(config, :organization)
      project = plan.mapping["project"]
      type = plan.mapping["work_item_type"] || "Task"
      url = "https://dev.azure.com/#{segment(org)}/#{segment(project)}/_apis/wit/workitems/$#{segment(type)}?api-version=7.1"
      body = [
        %{op: "add", path: "/fields/System.Title", value: plan.title},
        %{op: "add", path: "/fields/System.AreaPath", value: plan.mapping["area_path"]},
        %{op: "add", path: "/fields/System.Description", value: "<pre>#{escape(plan.description)}</pre>"}
      ]
      case Req.post(url, auth: {:basic, ":" <> Keyword.fetch!(config, :token)},
             headers: [{"content-type", "application/json-patch+json"}],
             body: Jason.encode!(body), retry: false, redirect: false,
             receive_timeout: 15_000, connect_options: [timeout: 5000]) do
        {:ok, %{status: status, body: %{"id" => id}}} when status in 200..299 and is_integer(id) and id > 0 ->
          {:ok, id, "https://dev.azure.com/#{segment(org)}/#{segment(project)}/_workitems/edit/#{id}"}
        {:ok, %{status: status}} when status in 400..499 and status != 408 -> {:error, :rejected}
        _ -> {:error, :unknown}
      end
    end
    defp segment(value), do: URI.encode(value, &URI.char_unreserved?/1)
    defp escape(value), do: value |> Phoenix.HTML.html_escape() |> Phoenix.HTML.safe_to_string()
  end
end
