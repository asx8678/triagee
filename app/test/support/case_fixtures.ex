defmodule Triage.CaseFixtures do
  @moduledoc "Stable synthetic estate for case-contract tests, independent of the evolving demo seed."
  import Triage.Fixtures, only: [image!: 1, placement!: 3, finding!: 3, event!: 3]
  alias Triage.Inventory.Image
  alias Triage.Repo

  @appeared ~U[2026-08-01 06:00:00Z]
  @resolved ~U[2026-08-05 06:00:00Z]
  @seen ~U[2026-09-09 06:00:00Z]

  def seed do
    image =
      Repo.insert!(%Image{
        digest: "sha256:aaa1111111111111111111111111111111111111111111111111111111111111",
        repository: "registry.internal/app-a",
        tag: "1.0"
      })

    for owner <- ["alpha", "beta"], do: placement!(image, owner, "prod")
    insert_finding(image, "CVE-2025-1001", package_name: "busybox", package_version: "1.37")

    insert_finding(image, "CVE-2024-2002",
      package_name: "openssl",
      package_version: "3.2.0",
      severity: "CRITICAL",
      fix: "3.2.1"
    )

    insert_finding(image, "CVE-2025-3003", package_name: "libc6", suppressed: true)

    resolved =
      insert_finding(image, "CVE-2023-5005", package_name: "gzip", resolved_at: @resolved)

    event!(resolved, "resolved", @resolved)

    unknown = image!("case-unknown")

    placement!(unknown, "alpha", "dev")
    |> Ecto.Changeset.change(namespace: "(unknown)")
    |> Repo.update!()

    insert_finding(unknown, "CVE-2024-4004", package_name: "zlib", package_version: "1.2.13")
    :ok
  end

  defp insert_finding(image, cve, opts) do
    finding = finding!(image, cve, Keyword.merge([first_seen: @appeared, last_seen: @seen], opts))
    event!(finding, "appeared", @appeared)
    finding
  end
end
