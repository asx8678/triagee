defmodule Triage.AiTriage.Runs do
  @moduledoc "Review click → captured evidence → durable Kiro job → scored result. No decision writes."
  import Ecto.Query
  import Ecto.Changeset, only: [change: 2]
  alias Triage.{Accounts, AiTriage, Canonical, Repo, Workspace}
  alias Triage.AiTriage.{Run, Worker}

  def request(cve, params, principal) when is_binary(cve) and is_map(params) do
    with {:ok, user} <- Accounts.authorize(principal, :review),
         :ok <- AiTriage.ready(),
         scope = scope(params),
         targets when targets != [] <- targets(cve, scope),
         input = AiTriage.snapshot(cve, targets),
         {:ok, _} <- AiTriage.prompt(input) do
      profile = AiTriage.profile()
      evidence_hash = AiTriage.snapshot_signature(input)
      identity = Canonical.hash({cve, scope, evidence_hash, profile})

      result =
        Repo.transaction(fn ->
          Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [identity])
          expire_interrupted(identity)

          Repo.one(
            from r in Run, where: r.identity == ^identity and r.state in ["queued", "running"]
          ) ||
            insert!(%Run{
              cve: cve,
              scope: scope,
              scope_key: Canonical.hash(scope),
              input: input,
              identity: identity,
              profile: profile,
              evidence_hash: evidence_hash,
              requested_by: user.id
            })
        end)

      broadcast(cve)
      result
    else
      [] -> {:error, :no_targets}
      error -> error
    end
  end

  def request(_, _, _), do: {:error, :invalid_request}

  def latest(cve, params) do
    key = Canonical.hash(scope(params))

    Repo.one(
      from r in Run,
        where: r.cve == ^cve and r.scope_key == ^key,
        order_by: [desc: r.id],
        limit: 1
    )
  end

  def current?(run) do
    run.profile == AiTriage.profile() and
      run.evidence_hash == AiTriage.signature(targets(run.cve, run.scope)) and
      DateTime.diff(now(), run.inserted_at) < 86_400
  end

  def display(nil), do: %{assessing: false, assessment: nil, error: nil}

  def display(run) do
    cond do
      not current?(run) or run.state == "stale" ->
        empty(
          "Evidence changed during analysis or since classification. Classify now to refresh the scores."
        )

      interrupted?(run) ->
        empty(
          "Classification was interrupted. Classify now to start a new run; no automatic retry was made."
        )

      run.state in ["queued", "running"] ->
        %{assessing: true, assessment: nil, error: nil}

      run.state == "failed" ->
        empty(error_message(run.error))

      run.state == "completed" ->
        %{assessing: false, assessment: run.result, error: nil}

      true ->
        empty("Classification is unavailable.")
    end
  end

  def perform(id) do
    case begin_run(id) do
      {:ok, {:run, run}} ->
        broadcast(run.cve)
        result = AiTriage.assess_snapshot(run.input)
        finish(run, result)

      _ ->
        :ok
    end
  rescue
    _ ->
      Repo.update_all(from(r in Run, where: r.id == ^id and r.state == "running"),
        set: [state: "failed", error: "runner_failed", finished_at: now()]
      )

      if run = Repo.get(Run, id), do: broadcast(run.cve)
      :ok
  end

  defp insert!(run) do
    run = Repo.insert!(run)
    Oban.insert!(Worker.new(%{run_id: run.id}))
    run
  end

  defp begin_run(id) do
    Repo.transaction(fn ->
      run = Repo.one(from r in Run, where: r.id == ^id, lock: "FOR UPDATE")

      cond do
        is_nil(run) or run.state != "queued" ->
          :done

        interrupted?(run) ->
          Repo.update!(change(run, state: "failed", error: "interrupted", finished_at: now()))
          broadcast(run.cve)
          :done

        not AiTriage.configured?() or not reviewer?(run.requested_by) ->
          Repo.update!(
            change(run, state: "failed", error: "not_enabled_or_authorized", finished_at: now())
          )

          broadcast(run.cve)
          :done

        not current?(run) ->
          Repo.update!(change(run, state: "stale", finished_at: now()))
          broadcast(run.cve)
          :done

        true ->
          {:run, Repo.update!(change(run, state: "running", started_at: now()))}
      end
    end)
  end

  defp finish(run, result) do
    {state, output, error} =
      case result do
        {:ok, output} -> {"completed", output |> Jason.encode!() |> Jason.decode!(), nil}
        {:error, error} -> {"failed", %{}, to_string(error)}
      end

    state =
      if current?(run) and AiTriage.enabled?() and reviewer?(run.requested_by),
        do: state,
        else: "stale"

    Repo.update_all(from(r in Run, where: r.id == ^run.id and r.state == "running"),
      set: [state: state, result: output, error: error, finished_at: now(), updated_at: now()]
    )

    broadcast(run.cve)
    :ok
  end

  defp interrupted?(run),
    do: run.state in ["queued", "running"] and DateTime.diff(now(), run.updated_at) > 180

  defp expire_interrupted(identity) do
    cutoff = DateTime.add(now(), -180, :second)

    Repo.update_all(
      from(r in Run,
        where:
          r.identity == ^identity and r.state in ["queued", "running"] and r.updated_at < ^cutoff
      ),
      set: [state: "failed", error: "interrupted", finished_at: now()]
    )
  end

  defp reviewer?(id) do
    case Repo.get(Accounts.User, id) do
      %{enabled: true} = user -> Accounts.permitted?(user, :review)
      _ -> false
    end
  end

  defp targets(cve, scope), do: Workspace.targets(Map.put(scope, "cve", cve))

  defp scope(params),
    do: params |> Map.take(~w(team environment)) |> Map.reject(fn {_, v} -> v in [nil, ""] end)

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp broadcast(cve),
    do:
      Phoenix.PubSub.broadcast(
        Triage.PubSub,
        "review:classification",
        {:classification_changed, cve}
      )

  defp empty(error), do: %{assessing: false, assessment: nil, error: error}

  defp error_message("invalid_response"),
    do: "Kiro returned an unexpected response format. No score was accepted."

  defp error_message("invalid_score"),
    do: "Kiro returned an invalid score. No score was accepted."

  defp error_message("timeout"),
    do: "Kiro timed out. Classify now to retry, or continue manual review."

  defp error_message("prompt_too_large"),
    do:
      "The full evidence exceeds the input limit. Narrow the team/environment scope; no evidence was silently dropped."

  defp error_message(_),
    do:
      "Kiro classification failed. Check the runner login/configuration and try Classify now again."
end
