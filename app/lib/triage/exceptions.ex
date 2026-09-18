defmodule Triage.Exceptions do
  @moduledoc """
  Local, time-limited exceptions; NEVER scanner suppression or remediation.

  Each decision belongs to one case (finding/package/version/image, owner and
  environment). Decisions are append-only audit records. A new decision or
  reopening increments the case revision under its existing row lock. Exact
  retries replay the original decision; conflicting tabs must reload.

  An exception is effective only until its UTC review date and while its saved
  snapshot AND revision remain current and the scoped source still matches.
  Changing evidence or recording a subsequent assessment requires a new decision.
  Reopening is allowed even when evidence is stale or a placement has retired.
  No reads, expiry checks, or exceptions write to scanner inventory or APIs.
  """
  import Ecto.Query
  alias Ecto.Changeset
  alias Triage.{Cases, Repo}
  alias Triage.Cases.ReviewCase
  alias Triage.Exceptions.Decision

  @max_id 9_223_372_036_854_775_807

  def change(attrs \\ %{}), do: attrs |> Decision.changeset() |> Decision.validate_review_date()

  def submit(case_id, revision, snapshot_id, token, attrs) do
    with true <- valid_id?(case_id) and valid_id?(revision) and valid_id?(snapshot_id),
         true <- is_binary(token) and byte_size(token) == 36,
         {:ok, token} <- Ecto.UUID.cast(token),
         changeset = Decision.changeset(attrs),
         true <- changeset.valid? or {:error, changeset} do
      save(case_id, revision, snapshot_id, token, changeset)
    else
      {:error, %Changeset{} = changeset} -> {:error, changeset}
      _ -> {:error, :invalid_request}
    end
  end

  def history(case_id) when is_integer(case_id) and case_id > 0 and case_id <= @max_id do
    Repo.all(from d in Decision, where: d.case_id == ^case_id, order_by: [desc: d.id])
  end

  # Only the projection needed for state; never send reasons, tokens or hashes
  # into queue rows. A batch is one query, independent of the number of cases.
  def latest_index([]), do: %{}

  def latest_index(case_ids) do
    Repo.all(
      from d in Decision,
        where: d.case_id in ^case_ids,
        distinct: d.case_id,
        order_by: [asc: d.case_id, desc: d.id],
        select: map(d, [:case_id, :kind, :snapshot_id, :expected_revision, :review_by])
    )
    |> Map.new(&{&1.case_id, &1})
  end

  def status(decision, binding, today \\ Date.utc_today())
  def status(nil, _binding, _today), do: :action_required
  def status(%{kind: "reopened"}, _binding, _today), do: :reopened

  def status(decision, binding, today) do
    cond do
      is_nil(decision.review_by) -> :needs_review
      Date.compare(decision.review_by, today) != :gt -> :expired
      binding.evidence_status != :current -> :needs_review
      decision.snapshot_id != binding.current_snapshot_id -> :needs_review
      decision.expected_revision + 1 != binding.revision -> :needs_review
      decision.kind == "accepted_risk" -> :accepted_risk
      decision.kind == "not_affected" -> :not_affected
      true -> :needs_review
    end
  end

  def decorate_rows(rows) do
    latest = latest_index(Enum.map(rows, & &1.id))
    Enum.map(rows, &Map.put(&1, :exception_status, status(latest[&1.id], &1)))
  end

  def finding_statuses(finding_ids) do
    finding_ids
    |> Cases.states_for_findings()
    |> decorate_rows()
    |> Map.new(&{{&1.finding_id, &1.owner, &1.environment}, &1.exception_status})
  end

  def binding(data),
    do: Map.put(Map.from_struct(data.case), :evidence_status, data.evidence_status)

  def label(:accepted_risk), do: "Temporarily suppressed locally — risk accepted"
  def label(:not_affected), do: "Not affected — operator evidence recorded"
  def label(:expired), do: "Action required — exception expired"
  def label(:needs_review), do: "Action required — exception needs review"
  def label(:reopened), do: "Action required — reopened"
  def label(_), do: "Action required — no local exception"

  defp save(case_id, revision, snapshot_id, token, changeset) do
    manual = Changeset.apply_changes(changeset)
    hash = request_hash(manual, revision, snapshot_id)

    Repo.transaction(fn ->
      cse = Repo.one(from c in ReviewCase, where: c.id == ^case_id, lock: "FOR UPDATE")
      if is_nil(cse), do: Repo.rollback(:not_found)
      replay = Repo.get_by(Decision, case_id: case_id, idempotency_token: token)

      cond do
        replay && replay.request_hash == hash ->
          %{decision: replay, replayed?: true}

        replay ->
          Repo.rollback(:token_reuse)

        cse.revision != revision or cse.current_snapshot_id != snapshot_id ->
          Repo.rollback(:conflict)

        true ->
          insert_decision(cse, token, hash, changeset)
      end
    end)
  end

  defp insert_decision(cse, token, hash, changeset) do
    changeset = Decision.validate_review_date(changeset)
    if not changeset.valid?, do: Repo.rollback(changeset)

    if Changeset.get_field(changeset, :kind) != "reopened" do
      case Cases.get_case(cse.id) do
        {:ok, %{evidence_status: :current}} -> :ok
        _ -> Repo.rollback(:evidence_stale)
      end
    end

    decision =
      changeset
      |> Changeset.change(
        case_id: cse.id,
        snapshot_id: cse.current_snapshot_id,
        expected_revision: cse.revision,
        idempotency_token: token,
        request_hash: hash,
        actor: "local-operator"
      )
      |> Repo.insert!()

    {1, _} = Repo.update_all(from(c in ReviewCase, where: c.id == ^cse.id), inc: [revision: 1])
    %{decision: decision, replayed?: false}
  end

  defp request_hash(manual, revision, snapshot_id) do
    payload =
      {"triage.exception.v1", revision, snapshot_id, manual.kind, manual.reason, manual.evidence,
       manual.review_by}

    :crypto.hash(:sha256, :erlang.term_to_binary(payload)) |> Base.encode16(case: :lower)
  end

  defp valid_id?(id), do: is_integer(id) and id > 0 and id <= @max_id
end
