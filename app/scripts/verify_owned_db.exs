case System.argv() do
  [expected, check] when check in ["config", "pristine", "identity", "empty"] ->
    partition = System.get_env("MIX_TEST_PARTITION")
    config = Triage.Repo.config()
    ecto_repos = Application.get_env(:triage, :ecto_repos)

    safe? =
      Mix.env() == :test and is_binary(expected) and
        Regex.match?(~r/^triage_test_ab_[A-Za-z0-9_]+$/, expected) and
        is_binary(partition) and Regex.match?(~r/^_ab_[A-Za-z0-9_]+$/, partition) and
        config[:database] == expected and expected == "triage_test#{partition}" and
        ecto_repos == [Triage.Repo] and config[:hostname] == "localhost" and
        config[:username] == "postgres" and Keyword.get(config, :port, 5432) == 5432 and
        is_nil(config[:url]) and is_nil(config[:socket]) and is_nil(config[:socket_dir])

    unless safe?, do: raise("owned database configuration mismatch")

    if check == "config" do
      IO.puts("verify-owned-db: configured Repo/host/user/port/database verified")
    else
      # Start Postgrex and its dependencies, but never the :triage application.
      {:ok, _} = Application.ensure_all_started(:postgrex)

      connection_options =
        config
        |> Keyword.take([:hostname, :port, :username, :password, :database])

      {:ok, pid} = Postgrex.start_link(connection_options)

      try do
        # This is deliberately the first statement on every database connection.
        %Postgrex.Result{rows: [[actual]]} = Postgrex.query!(pid, "SELECT current_database()", [])
        unless actual == expected, do: raise("owned database connection mismatch")

        if check == "pristine" do
          %Postgrex.Result{rows: rows} =
            Postgrex.query!(
              pid,
              """
              SELECT schemaname, tablename
              FROM pg_tables
              WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
              """,
              []
            )

          unless rows == [], do: raise("new owned database already has user tables")
        end

        if check == "empty" do
          tables =
            ~w(images image_placements findings finding_events review_cases review_evidence_snapshots review_reviews review_case_events replay_runs)

          Enum.each(tables, fn table ->
            %Postgrex.Result{rows: [[exists?]]} =
              Postgrex.query!(pid, "SELECT EXISTS (SELECT 1 FROM #{table})", [])

            if exists?, do: raise("owned database is populated: #{table}")
          end)
        end

        suffix = if check in ["pristine", "empty"], do: "; #{check} guard passed", else: ""
        IO.puts("verify-owned-db: configured/current database identity verified#{suffix}")
      after
        GenServer.stop(pid)
      end
    end

  _ ->
    raise("usage: verify_owned_db.exs EXPECTED_DB {config|pristine|identity|empty}")
end
