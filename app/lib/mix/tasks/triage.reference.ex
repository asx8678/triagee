defmodule Mix.Tasks.Triage.Reference do
  @shortdoc "Validate, download, preview or apply the real NVD reference catalogue"
  @moduledoc """
  Explicit reference data management, separate from scanning and intel refresh.

      mix triage.reference --check
      mix triage.reference --download
      mix triage.reference --preview
      mix triage.reference --apply --database triage_dev

  `--file PATH` overrides the checked-in catalogue. Check/download never start
  Repo or Endpoint. Preview is read-only. Apply validates the complete catalogue,
  confirms the configured/current local database name, retires only owned demo
  placements, and preserves unrelated inventory and all saved review history.
  No migration/reset occurs. Setup/ecto.seed use the offline catalogue by default.
  """
  use Mix.Task
  alias Triage.{CveCatalog, ReferenceCatalog, ReferenceData, Repo}

  @impl true
  def run(args) do
    {opts, rest, invalid} =
      OptionParser.parse(args,
        strict: [
          check: :boolean,
          download: :boolean,
          preview: :boolean,
          apply: :boolean,
          database: :string,
          file: :string
        ]
      )

    modes = Enum.filter([:check, :download, :preview, :apply], &Keyword.get(opts, &1, false))

    if invalid != [] or rest != [] or length(modes) != 1 or
         length(Keyword.keys(opts)) != length(Enum.uniq(Keyword.keys(opts))),
       do:
         Mix.raise(
           "Choose exactly one of --check, --download, --preview, --apply; no unknown or repeated options."
         )

    [mode] = modes

    if mode == :apply and Keyword.get(opts, :database, "") == "",
      do: Mix.raise("--apply requires --database with the exact configured local database name")

    if mode != :apply and Keyword.has_key?(opts, :database),
      do: Mix.raise("--database is only used with --apply")

    Mix.Task.run("compile", ["--quiet"])
    file = Keyword.get(opts, :file, ReferenceCatalog.path())

    result =
      case mode do
        :download ->
          with {:ok, catalog} <- CveCatalog.fetch(),
               :ok <- ReferenceCatalog.write(file, catalog),
               do: {:ok, catalog["counts"]}

        :check ->
          with {:ok, catalog} <- ReferenceCatalog.read(file), do: {:ok, catalog["counts"]}

        _ ->
          with {:ok, catalog} <- ReferenceCatalog.read(file) do
            start_repo!(mode, opts)

            if mode == :preview,
              do: ReferenceData.preview(catalog),
              else: ReferenceData.install(catalog)
          end
      end

    case result do
      {:ok, result} ->
        Mix.shell().info("Real NVD reference catalogue: #{inspect(result)}")

      {:error, reason} ->
        Mix.raise("Reference operation failed; no partial replacement: #{inspect(reason)}")
    end
  end

  defp start_repo!(mode, opts) do
    Mix.Task.run("app.config")
    config = Repo.config()

    unless config[:hostname] in ["localhost", "127.0.0.1", "::1"] and is_nil(config[:url]) and
             is_nil(config[:socket_dir]),
           do:
             Mix.raise(
               "Reference apply/preview is restricted to an explicit local database configuration"
             )

    expected = config[:database]

    if mode == :apply and Keyword.fetch!(opts, :database) != expected,
      do: Mix.raise("--database does not match the configured database; nothing changed")

    {:ok, _} = Application.ensure_all_started(:ecto_sql)
    {:ok, _} = Application.ensure_all_started(:postgrex)
    {:ok, _} = Repo.start_link()
    %{rows: [[^expected]]} = Repo.query!("SELECT current_database()")
    Mix.shell().info("Verified local database: #{expected}")
  end
end
