defmodule Triage.GuidedReview do
  @moduledoc "Actionable CVE queue and durable, per-team remediation requests. Never marks inventory fixed."
  import Ecto.Query
  alias Triage.{Decisions, Repo}

  defmodule Request do
    use Ecto.Schema

    schema "remediation_requests" do
      field :cve, :string
      field :owner, :string
      field :scope_key, :string
      field :status, :string, default: "planned"
      field :payload, :map
      field :ticket_id, :integer
      field :ticket_url, :string
      field :error, :string
      field :actor, :string
      timestamps(type: :utc_datetime)
    end
  end

  @doc "First bounded page of actionable CVEs. Use page/1 to traverse the full queue."
  def queue do
    {:ok, page} = page()
    page.rows
  end

  defdelegate page(opts \\ []), to: Triage.GuidedReview.Query
  defdelegate get(cve), to: Triage.GuidedReview.Query
  defdelegate actionable_for(cves), to: Triage.GuidedReview.Query

  @doc "Accepts risk only for the evidence the operator reviewed, independently of ticket configuration."
  def whitelist(cve, reason, expires_on, expected_fingerprint) do
    with true <- is_binary(reason) and String.length(String.trim(reason)) >= 3,
         true <- is_binary(expires_on),
         {:ok, date} <- Date.from_iso8601(expires_on),
         true <- Date.compare(date, Date.utc_today()) != :lt do
      case get(cve) do
        nil ->
          {:error, :review_changed}

        row ->
          accept_review(row, cve, reason, date, expected_fingerprint)
      end
    else
      _ -> {:error, :invalid_whitelist}
    end
  end

  defp accept_review(row, cve, reason, date, expected_fingerprint) do
    if is_binary(expected_fingerprint) and review_fingerprint(row) == expected_fingerprint do
      Decisions.record(%{
        cve: cve,
        decision: "accepted_risk",
        reason: String.trim(reason),
        actor: "local-operator",
        decided_at: DateTime.utc_now(),
        expires_at: DateTime.new!(date, ~T[23:59:59], "Etc/UTC")
      })
    else
      {:error, :review_changed}
    end
  end

  @doc "Fingerprint of all reviewed scopes, including teams already covered or ticketed."
  def review_fingerprint(row) do
    scopes =
      row.scopes
      |> Enum.map(fn scope ->
        %{
          finding:
            Map.take(scope.finding, [
              :id,
              :cve,
              :package_name,
              :package_version,
              :severity,
              :fix,
              :description,
              :first_seen,
              :reopen_count
            ]),
          placement: Map.take(scope.placement, [:id, :owner, :environment, :namespace, :active]),
          image: Map.take(scope.image, [:id, :digest, :repository, :tag]),
          exposure: scope.exposure,
          covered?: scope.covered?,
          risk: scope.risk
        }
      end)
      |> Enum.sort()

    {row.cve, scopes}
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16()
  end

  def preview(cve) do
    case get(cve) do
      nil -> {:error, :not_actionable}
      row -> {:ok, Enum.map(row.pending, &ticket_plan(row, &1))}
    end
  end

  defp ticket_plan(row, team) do
    mapping = Triage.ReviewIntegrations.team_mapping(team.owner)

    %{
      cve: row.cve,
      owner: team.owner,
      scope_key: team.scope_key,
      mapping: mapping,
      request: team.request,
      organization: Keyword.get(Triage.ReviewIntegrations.config(), :organization),
      title: "Fix #{row.cve} — #{team.owner}",
      description:
        Enum.join(
          [
            "CVE: #{row.cve}",
            "Responsible team: #{team.owner}",
            "Review priority: #{row.risk.priority} (local policy, not CVSS)",
            Enum.join(row.descriptions, "\n\n"),
            "Affected services and libraries:",
            Enum.map_join(team.scopes, "\n", fn s ->
              "#{s.image.repository}:#{s.image.tag} | #{s.placement.environment} | #{s.finding.package_name} #{s.finding.package_version} | fix: #{s.finding.fix || "not reported"} | exposure: #{s.exposure}"
            end),
            "Created by local-operator. Ticket creation is not evidence of a deployed fix."
          ],
          "\n\n"
        )
    }
  end

  # Preview fingerprint binds confirmation to the current scope and destination.
  def fingerprint(plans) do
    plans
    |> Enum.map(
      &Map.take(&1, [:cve, :owner, :scope_key, :organization, :mapping, :title, :description])
    )
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16()
  end

  @doc "Atomically plans up to 25 explicitly previewed CVEs; never sends tickets or accepts risk."
  def bulk_mark_for_fix(reviews) when is_map(reviews) and map_size(reviews) in 1..25 do
    Repo.transaction(fn ->
      plans =
        Enum.flat_map(reviews, fn {cve, expected} ->
          case get(cve) do
            nil ->
              Repo.rollback(:review_changed)

            row ->
              if review_fingerprint(row) != expected, do: Repo.rollback(:review_changed)
              Enum.map(row.pending, &ticket_plan(row, &1))
          end
        end)

      Enum.map(plans, &persist/1)
    end)
  end

  def bulk_mark_for_fix(_), do: {:error, :invalid_selection}

  def mark_for_fix(cve) do
    with {:ok, plans} <- preview(cve) do
      Repo.transaction(fn -> Enum.map(plans, &persist/1) end)
    end
  end

  defp persist(plan) do
    payload = ticket_payload(plan)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.insert!(
      %Request{
        cve: plan.cve,
        owner: plan.owner,
        scope_key: plan.scope_key,
        payload: payload,
        actor: "local-operator",
        inserted_at: now,
        updated_at: now
      },
      on_conflict: :nothing,
      conflict_target: [:cve, :owner, :scope_key]
    )

    Repo.one!(
      from r in Request,
        where: r.cve == ^plan.cve and r.owner == ^plan.owner and r.scope_key == ^plan.scope_key
    )
  end

  # Persist the same immutable content/destination that the adapter receives.
  # This is also written atomically with the send claim, not on a losing retry.
  defp ticket_payload(plan),
    do: Map.take(plan, [:title, :description, :mapping, :organization])

  def create_tickets(cve, expected_fingerprint) do
    with {:ok, plans} <- preview(cve),
         true <- fingerprint(plans) == expected_fingerprint,
         true <- Triage.ReviewIntegrations.azure_configured?(),
         true <- Enum.all?(plans, & &1.mapping) do
      {:ok, Enum.map(plans, fn plan -> plan |> persist() |> send_ticket(plan) end)}
    else
      false -> {:error, :preview_changed_or_configuration_missing}
      error -> error
    end
  end

  defp send_ticket(request, plan) do
    # Claim is durable before the external write. A crash or ambiguous network
    # response must never cause an automatic duplicate ticket on retry.
    {claimed, _} =
      Repo.update_all(
        from(r in Request,
          where: r.id == ^request.id and r.status in ["planned", "failed"]
        ),
        set: [
          status: "sending",
          payload: ticket_payload(plan),
          error: nil,
          updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
        ]
      )

    if claimed == 1 do
      request = Repo.get!(Request, request.id)
      result = Triage.ReviewIntegrations.create_ticket(plan)

      attrs =
        case result do
          {:ok, id, url} ->
            %{status: "created", ticket_id: id, ticket_url: url, error: nil}

          {:error, :rejected} ->
            %{
              status: "failed",
              error: "Azure rejected this request. Check configuration before retrying."
            }

          _ ->
            %{
              status: "unknown",
              error:
                "Creation could not be confirmed. Check Azure before any manual retry; automatic retry is blocked."
            }
        end

      request |> Ecto.Changeset.change(attrs) |> Repo.update!()
    else
      Repo.get!(Request, request.id)
    end
  end

  def requests(cve),
    do: Repo.all(from r in Request, where: r.cve == ^cve, order_by: [asc: r.owner, desc: r.id])
end
