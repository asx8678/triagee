defmodule Triage.Collection do
  @moduledoc """
  Offline-first, read-only collection adapter for the security GraphQL source.

  The default entry is DISABLED and the loopback transport is compile-time
  test-only: a production build (dev/prod release) always returns
  `{:error, %DisabledError{}}` and never performs network access, even when a
  config and transport are passed. Only test builds may use the fixed
  `Transport.Req` transport against the literal `http://127.0.0.1` endpoint of a
  validated `Config`. Collection never writes the inventory and references no
  `Triage.Repo`.

  Options:

    * `:config` — a `Triage.Collection.Config` or the plain map/keyword accepted
      by `Config.new/1`. Required for an enabled crawl.
    * `:transport` — `nil` (disabled) or the fixed test transport
      `{Transport.Req, %Transport.Req{}}`. Arbitrary transport modules are
      rejected.
    * `:signal` — a zero-arity cancellation predicate. A stalling callback is
      bounded by the outer deadline.
    * `:owners` — restrict the crawl to explicit nonblank owner strings.
    * `:max_images` — bound the number of image detail requests.
  """

  alias Triage.Collection.{Config, Crawl, Transport}
  alias Triage.Collection.Errors.{DisabledError, InvalidOptionsError}

  @allowed_opts ~w(config transport signal owners max_images)a

  @doc "Runs a bounded, read-only crawl and returns `{:ok, %Report{}}`."
  def run(opts \\ [])

  def run(opts) when is_list(opts) do
    with :ok <- validate_opts(opts),
         {:ok, opts} <- validate_runtime(opts),
         {:ok, config} <- resolve_config(Keyword.get(opts, :config)),
         {:ok, {transport, state}} <- resolve_transport(Keyword.get(opts, :transport)) do
      Crawl.run(config, transport, state, opts)
    end
  end

  def run(_other) do
    {:error, %InvalidOptionsError{message: "options must be a keyword list"}}
  end

  defp validate_opts(opts) do
    if Keyword.keyword?(opts) do
      case Enum.find(opts, fn {key, _value} -> key not in @allowed_opts end) do
        nil -> :ok
        {key, _value} -> {:error, %InvalidOptionsError{message: "unknown option #{inspect(key)}"}}
      end
    else
      {:error, %InvalidOptionsError{message: "options must be a keyword list of known keys"}}
    end
  end

  defp validate_runtime(opts) do
    with {:ok, owners} <- validate_owners(Keyword.get(opts, :owners)),
         {:ok, max_images} <- validate_max_images(Keyword.get(opts, :max_images)),
         {:ok, signal} <- validate_signal(Keyword.get(opts, :signal)) do
      {:ok,
       opts
       |> Keyword.put(:owners, owners)
       |> Keyword.put(:max_images, max_images)
       |> Keyword.put(:signal, signal)}
    end
  end

  defp validate_owners(nil), do: {:ok, nil}

  defp validate_owners(owners) when is_list(owners) do
    if Enum.all?(owners, &(is_binary(&1) and String.trim(&1) != "")) do
      {:ok, owners}
    else
      {:error, %InvalidOptionsError{message: "owners must be a list of nonblank strings"}}
    end
  end

  defp validate_owners(_other),
    do: {:error, %InvalidOptionsError{message: "owners must be a list"}}

  defp validate_max_images(nil), do: {:ok, nil}

  defp validate_max_images(value) when is_integer(value) and value >= 1 and value <= 100_000,
    do: {:ok, value}

  defp validate_max_images(_other),
    do: {:error, %InvalidOptionsError{message: "max_images must be a positive integer"}}

  defp validate_signal(nil), do: {:ok, nil}
  defp validate_signal(fun) when is_function(fun, 0), do: {:ok, fun}

  defp validate_signal(_other),
    do: {:error, %InvalidOptionsError{message: "signal must be a zero-arity function"}}

  defp resolve_config(nil) do
    {:error,
     %DisabledError{message: "offline: no collection config; live collection is disabled"}}
  end

  defp resolve_config(%Config{} = config), do: Config.revalidate(config)

  defp resolve_config(opts) when is_list(opts) or is_map(opts), do: Config.new(opts)

  defp resolve_config(_other) do
    {:error, %InvalidOptionsError{message: "config must be a Config struct or plain options"}}
  end

  defp resolve_transport(nil), do: {:ok, {Transport.Disabled, nil}}

  defp resolve_transport({Transport.Disabled, state}), do: {:ok, {Transport.Disabled, state}}

  if Mix.env() == :test do
    defp resolve_transport({Transport.Req, %Transport.Req{} = state}) do
      {:ok, {Transport.Req, state}}
    end
  else
    defp resolve_transport({Transport.Req, %Transport.Req{} = _state}) do
      {:error, %DisabledError{message: "offline: live collection is disabled"}}
    end
  end

  defp resolve_transport({Transport.Req, _other}) do
    {:error,
     %InvalidOptionsError{message: "Transport.Req must be constructed with Transport.Req.new/1"}}
  end

  defp resolve_transport(_other) do
    {:error, %InvalidOptionsError{message: "transport must be the fixed loopback transport"}}
  end
end
