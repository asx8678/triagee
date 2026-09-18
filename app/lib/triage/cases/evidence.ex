defmodule Triage.Cases.Evidence do
  @moduledoc "Internal pure evidence encoding shared by case writes and read models. Hash domains and payload shape are stable."
  alias Triage.Cases.ReviewCase

  @payload_source "synthetic_local_inventory"
  @payload_schema_version 1

  # Deterministic content hashing: fixed domain markers plus a canonical
  # encoder (sorted maps, length-tagged scalars) — never Jason map iteration
  # order and never unchecked string concatenation of untrusted delimiters.
  @hash_domain "triage.cases.evidence.v1"
  @request_hash_domain "triage.cases.review_request.v1"

  @coverage %{
    "kind" => "local_synthetic_only",
    "warning" =>
      "Evidence was captured from the local synthetic inventory only. " <>
        "Production coverage is unknown and this snapshot is not a completeness assertion."
  }

  def request_hash(manual, expected_revision, expected_snapshot_id) do
    canonical_hash(@request_hash_domain, %{
      "manual" => manual,
      "expected_revision" => expected_revision,
      "expected_snapshot_id" => expected_snapshot_id
    })
  end

  ## Frozen evidence payload and deterministic content hashing

  # The stable snapshot payload shape (schema_version 1). Only captured facts:
  # no ORM inserted_at/updated_at, no capture time (that is separate
  # `captured_at` metadata), so the content hash is stable across reads and
  # recomputations.
  def build_snapshot(%ReviewCase{owner: owner, environment: environment}, data) do
    built = payload(owner, environment, data)
    {built, content_hash(built)}
  end

  defp payload(owner, environment, data) do
    %{
      "schema_version" => @payload_schema_version,
      "source" =>
        if(Triage.ReferenceData.reference_image?(data.finding.image),
          do: "nvd_public_reference",
          else: @payload_source
        ),
      "scope" => %{"owner" => owner, "environment" => environment},
      "finding" => finding_payload(data.finding),
      "image" => image_payload(data.finding.image),
      "placements" => placements_payload(data.placements),
      "events" => lifecycle_payload(data.events),
      "coverage" =>
        if(Triage.ReferenceData.reference_image?(data.finding.image),
          do: %{"kind" => "public_reference_only", "warning" => Triage.ReferenceData.warning()},
          else: @coverage
        )
    }
  end

  defp finding_payload(finding) do
    %{
      "id" => finding.id,
      "image_id" => finding.image_id,
      "cve" => finding.cve,
      "package_name" => finding.package_name,
      "package_version" => finding.package_version,
      "severity" => finding.severity,
      "fix" => finding.fix,
      "url" => finding.url,
      "description" => finding.description,
      "suppressed" => finding.suppressed,
      "first_seen" => iso8601(finding.first_seen),
      "last_seen" => iso8601(finding.last_seen),
      "resolved_at" => iso8601(finding.resolved_at),
      "reopen_count" => finding.reopen_count
    }
  end

  defp image_payload(image) do
    %{
      "id" => image.id,
      "digest" => image.digest,
      "repository" => image.repository,
      "tag" => image.tag,
      "description" => image.description
    }
  end

  defp placements_payload(placements) do
    placements
    |> Enum.map(fn placement ->
      %{
        "id" => placement.id,
        "owner" => placement.owner,
        "namespace" => placement.namespace,
        "environment" => placement.environment,
        "active" => placement.active,
        "first_seen" => iso8601(placement.first_seen),
        "last_seen" => iso8601(placement.last_seen)
      }
    end)
    |> Enum.sort_by(&{&1["owner"], &1["namespace"], &1["environment"], &1["id"]})
  end

  defp lifecycle_payload(events) do
    events
    |> Enum.sort_by(&{&1.occurred_at, &1.id})
    |> Enum.map(fn event ->
      %{
        "id" => event.id,
        "event" => event.event,
        "occurred_at" => iso8601(event.occurred_at),
        "note" => event.note
      }
    end)
  end

  defp iso8601(nil), do: nil
  defp iso8601(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)

  defp content_hash(value), do: canonical_hash(@hash_domain, value)

  defp canonical_hash(domain, value) do
    :crypto.hash(:sha256, domain <> "|" <> canonical(value))
    |> Base.encode16(case: :lower)
  end

  # Canonical structured-content encoding: nil/bool/int tagged by type,
  # binaries length-tagged (no delimiter ambiguity), lists explicit, maps
  # sorted by encoded key so query and map insertion order are irrelevant.
  defp canonical(nil), do: "n"
  defp canonical(true), do: "t"
  defp canonical(false), do: "f"

  defp canonical(value) when is_integer(value), do: "i" <> Integer.to_string(value)

  defp canonical(value) when is_binary(value),
    do: "s" <> Integer.to_string(byte_size(value)) <> ":" <> value

  defp canonical(value) when is_list(value) do
    "l[" <> Enum.map_join(value, ",", &canonical/1) <> "]"
  end

  defp canonical(value) when is_map(value) do
    "m{" <>
      (value
       |> Enum.map(fn {key, item} -> canonical(key) <> "=" <> canonical(item) end)
       |> Enum.sort()
       |> Enum.join(",")) <>
      "}"
  end
end
