defmodule Triage.ReferenceData do
  @moduledoc """
  Installs validated real public advisories into a clearly labelled reference
  scope. This is NOT a scan of a deployed image. Atomic, repeatable, and scoped:
  legacy fixture placements are retired, never history-deleted or marked fixed.
  """
  import Ecto.Query
  alias Triage.{Inventory, ReferenceCatalog, Repo}

  @repository "public-reference/nvd-catalogue"
  @owner "public-reference"
  @environment "not-a-deployment"
  @namespace "reference-only"
  @version "Not assessed (public reference)"
  @prefix "NVD PUBLIC REFERENCE — "
  @warning "Real NVD advisory data, not a scanner finding or evidence of an affected deployment. Image digest identifies this catalogue, not a container. Installed version, exposure and remediation are not assessed. Reference load times are not detection or publication times."
  @legacy [
    {"sha256:aaa1111111111111111111111111111111111111111111111111111111111111",
     "registry.internal/app-a", "1.0", "Synthetic service A image",
     [{"alpha", "web"}, {"beta", "web"}],
     [
       {"CVE-2025-1001", "busybox", "1.37"},
       {"CVE-2025-1001", "busybox-binsh", "1.37"},
       {"CVE-2024-2002", "openssl", "3.1"},
       {"CVE-2024-4004", "zlib", "1.3"},
       {"CVE-2023-5005", "gzip", "1.12"}
     ]},
    {"sha256:bbbb222222222222222222222222222222222222222222222222222222222222",
     "registry.internal/app-b", "2.0", "Synthetic service B image", [{"beta", "web"}],
     [
       {"CVE-2025-1001", "curl", "8.5"},
       {"CVE-2025-3003", "libc6", "2.36"}
     ]},
    {"sha256:cccc333333333333333333333333333333333333333333333333333333333333",
     "registry.internal/shared-base", "9", "Synthetic shared base image",
     [{"alpha", "(unknown)"}],
     [
       {"CVE-2024-4004", "zlib", "1.2.13"}
     ]}
  ]

  def warning, do: @warning
  def owner, do: @owner
  def environment, do: @environment
  def legacy_digests, do: Enum.map(@legacy, &elem(&1, 0))

  def reference_image?(%{repository: @repository, tag: "reference", description: description})
      when is_binary(description), do: String.starts_with?(description, @prefix)

  def reference_image?(_), do: false

  def seed! do
    with {:ok, catalog} <- ReferenceCatalog.read(), {:ok, result} <- install(catalog) do
      result
    else
      {:error, reason} -> raise "Real CVE reference seed failed: #{inspect(reason)}"
    end
  end

  def preview(catalog) do
    with {:ok, _} <- ReferenceCatalog.validate(catalog) do
      Repo.transaction(fn ->
        legacy = legacy_images!()

        %{
          counts: catalog["counts"],
          legacy_images_to_retire: length(legacy),
          reference_scope: {@owner, @environment},
          history_deleted: false
        }
      end)
    end
  end

  def install(catalog) do
    with {:ok, _} <- ReferenceCatalog.validate(catalog) do
      Repo.transaction(fn ->
        Repo.query!("SELECT pg_advisory_xact_lock($1)", [Triage.Import.Contract.lock_key()])
        legacy = legacy_images!()
        reference = Repo.all(from i in Inventory.Image, where: i.repository == ^@repository)
        Enum.each(reference, &validate_reference_image!/1)
        now = DateTime.utc_now() |> DateTime.truncate(:second)
        image = ensure_image!(catalog)
        ensure_placement!(image, now)
        Enum.each(catalog["advisories"], &ensure_finding!(image, &1, catalog["fetched_at"], now))

        unless Repo.aggregate(
                 from(f in Inventory.Finding, where: f.image_id == ^image.id),
                 :count
               ) == 95,
               do: Repo.rollback(:modified_reference_finding)

        retired_ids = Enum.map(legacy ++ Enum.reject(reference, &(&1.id == image.id)), & &1.id)

        {retired, _} =
          Repo.update_all(
            from(p in Inventory.ImagePlacement,
              where: p.image_id in ^retired_ids and p.active == true
            ),
            set: [active: false]
          )

        retire_synthetic_news!()

        %{
          counts: catalog["counts"],
          image_id: image.id,
          retired_placements: retired,
          reference_scope: {@owner, @environment},
          history_deleted: false
        }
      end)
    end
  end

  # Only owned retired fixture/reference images disappear from advisory aggregates.
  # Other inactive inventory keeps its prior browsing semantics; case history is untouched.
  def retired_image_ids do
    digests = legacy_digests()
    active = from p in Inventory.ImagePlacement, where: p.active, select: p.image_id

    from i in Inventory.Image,
      where: i.digest in ^digests or i.repository == ^@repository,
      where: i.id not in subquery(active),
      select: i.id
  end

  def active_counts do
    rows =
      Repo.all(
        from f in Inventory.Finding,
          join: i in Inventory.Image,
          on: i.id == f.image_id,
          join: p in Inventory.ImagePlacement,
          on: p.image_id == i.id,
          where:
            i.repository == ^@repository and p.active and p.owner == ^@owner and
              p.environment == ^@environment,
          group_by: f.severity,
          select: {f.severity, count(f.cve, :distinct)}
      )

    Map.new(rows)
  end

  defp legacy_images! do
    Enum.flat_map(@legacy, fn {digest, repo, tag, description, scopes, identities} ->
      case Repo.get_by(Inventory.Image, digest: digest) do
        nil ->
          []

        image ->
          unless {image.repository, image.tag, image.description} == {repo, tag, description},
            do: Repo.rollback(:modified_legacy_image)

          findings = Repo.all(from f in Inventory.Finding, where: f.image_id == ^image.id)

          unless Enum.all?(
                   findings,
                   &({&1.cve, &1.package_name, &1.package_version} in identities)
                 ),
                 do: Repo.rollback(:unrelated_findings_on_legacy_image)

          placements =
            Repo.all(from p in Inventory.ImagePlacement, where: p.image_id == ^image.id)

          unless Enum.all?(
                   placements,
                   &(&1.environment == "prod-cluster-1" and {&1.owner, &1.namespace} in scopes)
                 ),
                 do: Repo.rollback(:unrelated_placements_on_legacy_image)

          [image]
      end
    end)
  end

  defp validate_reference_image!(image) do
    unless reference_image?(image), do: Repo.rollback(:reference_identity_collision)
    placements = Repo.all(from p in Inventory.ImagePlacement, where: p.image_id == ^image.id)

    unless Enum.all?(
             placements,
             &({&1.owner, &1.environment, &1.namespace} == {@owner, @environment, @namespace})
           ),
           do: Repo.rollback(:unrelated_reference_placement)

    findings = Repo.all(from f in Inventory.Finding, where: f.image_id == ^image.id)

    unless Enum.all?(
             findings,
             &(&1.package_version == @version and is_binary(&1.description) and
                 String.starts_with?(&1.description, @prefix))
           ),
           do: Repo.rollback(:unrelated_reference_finding)
  end

  defp ensure_image!(catalog) do
    fingerprint =
      :crypto.hash(
        :sha256,
        :erlang.term_to_binary(
          {"triage.nvd-reference.v1", catalog["fetched_at"], catalog["advisories"]},
          [:deterministic]
        )
      )
      |> Base.encode16(case: :lower)

    attrs = %{
      digest: "sha256:" <> fingerprint,
      repository: @repository,
      tag: "reference",
      description: @prefix <> @warning <> " Fetched " <> catalog["fetched_at"]
    }

    case Repo.get_by(Inventory.Image, digest: attrs.digest) do
      nil ->
        Repo.insert!(Inventory.Image.changeset(%Inventory.Image{}, attrs))

      image ->
        unless Map.take(Map.from_struct(image), Map.keys(attrs)) == attrs,
          do: Repo.rollback(:reference_identity_collision)

        image
    end
  end

  defp ensure_placement!(image, now) do
    case Repo.get_by(Inventory.ImagePlacement,
           image_id: image.id,
           namespace: @namespace,
           owner: @owner,
           environment: @environment
         ) do
      nil ->
        {:ok, _} =
          Inventory.upsert_placement(
            image,
            %{namespace: @namespace, owner: @owner, environment: @environment},
            now
          )

      %{active: true} ->
        :ok

      _ ->
        Repo.rollback(:retired_catalog_requires_explicit_new_download)
    end
  end

  defp ensure_finding!(image, row, fetched_at, now) do
    attrs = %{
      image_id: image.id,
      cve: row["cve"],
      package_name: product_name(row),
      package_version: @version,
      severity: row["severity"],
      fix: nil,
      url: row["url"],
      description: description(row, fetched_at),
      suppressed: false
    }

    case Repo.all(
           from f in Inventory.Finding,
             where: f.image_id == ^image.id and f.cve == ^attrs.cve,
             limit: 2
         ) do
      [] ->
        finding =
          Repo.insert!(
            Inventory.Finding.changeset(
              %Inventory.Finding{},
              Map.merge(attrs, %{first_seen: now, last_seen: now})
            )
          )

        Inventory.record_event(
          finding.id,
          "appeared",
          now,
          "NVD reference catalogue loaded; not a scanner detection."
        )

      [existing] ->
        unless Map.take(Map.from_struct(existing), Map.keys(attrs)) == attrs and
                 is_nil(existing.resolved_at) and existing.reopen_count == 0,
               do: Repo.rollback(:modified_reference_finding)

      _ ->
        Repo.rollback(:modified_reference_finding)
    end
  end

  defp product_name(row) do
    case row["affected_products"] do
      [%{"criteria" => criteria} | _] ->
        case Regex.run(~r/^cpe:2\.3:[aho]:([^:\\]+):([^:\\]+):/, criteria) do
          [_, vendor, product] -> vendor <> "/" <> product
          _ -> "Affected product not supplied"
        end

      _ ->
        "Affected product not supplied"
    end
  end

  defp description(row, fetched_at) do
    @prefix <>
      "Not a scanner observation.\n" <>
      "Source: #{row["url"]}\nFetched: #{fetched_at}\n" <>
      "CVSS #{row["cvss_version"]}: #{row["cvss_score"]} #{row["severity"]}; metric author: #{row["metric_source"]}\n" <>
      "Vector: #{row["cvss_vector"]}\nPublished: #{row["published_at"]}; modified: #{row["last_modified_at"]}\n\n" <>
      row["description"] <>
      "\n\nAffected-product evidence (CPE/ranges; not an installed version):\n" <>
      Jason.encode!(row["affected_products"])
  end

  defp retire_synthetic_news! do
    Repo.delete_all(
      from n in Triage.Intel.NewsItem,
        where:
          n.source == "synthetic" and
            ((n.item_id == "demo-1" and n.link == "https://example.invalid/demo-1") or
               (n.item_id == "demo-2" and n.link == "https://example.invalid/demo-2"))
    )
  end
end
