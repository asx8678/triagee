case System.argv() do
  [expected, check] when check in ["config", "pristine", "identity", "empty"] ->
    partition = System.get_env("MIX_TEST_PARTITION")

    # The owned-port override is re-validated here against the same rule the
    # wrapper enforces, so the identity check compares against a port that was
    # proven valid — anything else fails closed before any connection.
    expected_port =
      case System.get_env("TRIAGE_OWNED_DB_PORT") do
        nil ->
          5432

        text ->
          case Integer.parse(text) do
            {port, ""} when port >= 1024 and port <= 65_535 -> port
            _ -> raise("invalid TRIAGE_OWNED_DB_PORT")
          end
      end

    config = Triage.Repo.config()
    ecto_repos = Application.get_env(:triage, :ecto_repos)

    safe? =
      Mix.env() == :test and is_binary(expected) and
        Regex.match?(~r/^triage_test_ab_[A-Za-z0-9_]+$/, expected) and
        is_binary(partition) and Regex.match?(~r/^_ab_[A-Za-z0-9_]+$/, partition) and
        config[:database] == expected and expected == "triage_test#{partition}" and
        ecto_repos == [Triage.Repo] and config[:hostname] == "localhost" and
        config[:username] == "postgres" and Keyword.get(config, :port, 5432) == expected_port and
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
          # Discover all migrated application tables, including auth, drafts and
          # durable integrations; a fixed list silently misses future migrations.
          %Postgrex.Result{rows: tables} =
            Postgrex.query!(
              pid,
              """
              SELECT quote_ident(schemaname) || '.' || quote_ident(tablename)
              FROM pg_tables
              WHERE schemaname = 'public' AND tablename <> 'schema_migrations'
              ORDER BY tablename
              """,
              []
            )

          Enum.each(tables, fn [table] ->
            # Only the exact migration-created safety singleton may exist.
            # Extra rows or any pause/revision/reason change remain populated.
            query =
              if table == "public.classifier_controls" do
                "SELECT NOT (count(*) = 1 AND bool_and(id = 1 AND paused = false AND revision = 1 AND reason = 'Initial state; runtime remains default-off')) FROM #{table}"
              else
                "SELECT EXISTS (SELECT 1 FROM #{table})"
              end

            %Postgrex.Result{rows: [[exists?]]} = Postgrex.query!(pid, query, [])
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
