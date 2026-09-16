defmodule Triage.Collection.Transport do
  @moduledoc """
  Transport contract for offline collection.

  A transport is fixed, not arbitrary: the only network-capable transport is
  `Transport.Req`, which is compile-time gated by
  `config :triage, :collection, loopback_transport` (enabled only by
  `config/test.exs`) and only ever posts to the literal `http://127.0.0.1`
  loopback endpoint of its validated
  `Config`. The default (`Disabled`) performs no network access. `post/3`
  revalidates its state, so a forged state map or struct cannot bypass the gate.

  The wire headers are fixed by the transport itself (`content-type` and
  `accept` `application/json`); caller-supplied or forged `headers` are never
  sent. A state carrying any injected headers is rejected, and a forged
  `error` is replaced by a constant sanitized error rather than forwarded.
  """

  alias Triage.Collection.Errors.{
    DisabledError,
    InvalidOptionsError
  }

  # Compile-time gate, read from the one shared definition in
  # `Triage.Collection.Loopback` so this module, `Triage.Collection` and the
  # nested `Req` module cannot drift apart. The guarantee is unchanged: the value
  # is baked in when this module is compiled, so a release still cannot enable
  # the loopback path at runtime.
  @loopback_enabled Triage.Collection.Loopback.enabled?()

  @doc "True only when this build was compiled with the loopback transport enabled."
  @spec loopback_enabled?() :: boolean()
  def loopback_enabled?, do: @loopback_enabled

  @type result ::
          {:ok, %{status: non_neg_integer(), headers: map(), body: binary()}}
          | {:error, term()}

  @callback post(state :: term(), body :: binary(), opts :: keyword()) :: result()

  defmodule Disabled do
    @moduledoc "Default offline transport: always fails without touching the network."
    @behaviour Triage.Collection.Transport

    @impl true
    def post(_state, _body, _opts) do
      {:error, %DisabledError{message: "offline: no live collection transport configured"}}
    end
  end

  defmodule Req do
    @moduledoc """
    The fixed loopback transport over `Req`.

    Compile-time test-only and endpoint-validated. The request is built from a
    bare `Req.Request` with the built-in steps attached, so ambient
    `Req.default_options/1` (adapter, TLS `connect_options`, base URL, auth)
    cannot be inherited. Redirects and retries are disabled; the response body is
    streamed and halted at the byte budget before any decode, and a returned body
    is byte-checked again. Headers are always the fixed pair; forged headers are
    rejected.
    """

    @behaviour Triage.Collection.Transport

    # Module attributes are not inherited by nested modules, so the shared
    # compile-time value is read again here rather than restated.
    @loopback_enabled Triage.Collection.Loopback.enabled?()

    defstruct [:endpoint, :headers, :request_timeout_ms, :max_response_bytes, :error]

    @doc "Builds the transport state from a validated `Config`."
    def new(%Triage.Collection.Config{} = config) do
      case Triage.Collection.Config.revalidate(config) do
        {:ok, valid} ->
          %__MODULE__{
            endpoint: valid.endpoint,
            headers: [],
            request_timeout_ms: valid.request_timeout_ms,
            max_response_bytes: valid.max_response_bytes,
            error: nil
          }

        {:error, error} ->
          invalid_state(error)
      end
    end

    def new(_other),
      do:
        invalid_state(%InvalidOptionsError{
          message: "transport requires a validated Config struct"
        })

    @impl true
    def post(%__MODULE__{error: error}, _body, _opts) when not is_nil(error) do
      {:error, %InvalidOptionsError{message: "transport state is invalid"}}
    end

    if @loopback_enabled do
      def post(%__MODULE__{} = state, body, opts) when is_binary(body) do
        case validate_state(state, opts) do
          {:ok, endpoint, timeout, max} -> do_post(endpoint, body, timeout, max)
          {:error, error} -> {:error, error}
        end
      end
    else
      def post(%__MODULE__{} = _state, _body, _opts) do
        {:error, %DisabledError{message: "offline: live collection is disabled"}}
      end
    end

    def post(_state, _body, _opts) do
      {:error, %InvalidOptionsError{message: "transport requires a Transport.Req state struct"}}
    end

    defp invalid_state(error) do
      %__MODULE__{
        endpoint: nil,
        headers: [],
        request_timeout_ms: 1,
        max_response_bytes: 1,
        error: error
      }
    end

    # The live request path is compiled only for tests (dev and prod are offline by
    # construction), so its helpers are defined only where they can be called.
    if @loopback_enabled do
      alias Triage.Collection.Errors

      alias Triage.Collection.Errors.{ResponseBudgetError, TransportError}

      @dropped_headers ~w(set-cookie cookie authorization proxy-authorization location)

      @fixed_headers [{"content-type", "application/json"}, {"accept", "application/json"}]

      defp validate_state(state, opts) do
        timeout = Keyword.get(opts, :receive_timeout, state.request_timeout_ms)
        max = Keyword.get(opts, :max_response_bytes, state.max_response_bytes)

        cond do
          not Triage.Collection.Config.endpoint_allowed?(state.endpoint) ->
            {:error,
             %InvalidOptionsError{message: "endpoint is not an allowed loopback endpoint"}}

          state.headers != [] ->
            {:error, %InvalidOptionsError{message: "transport headers must remain empty"}}

          not (is_integer(timeout) and timeout >= 1 and timeout <= 120_000) ->
            {:error, %InvalidOptionsError{message: "receive_timeout is out of range"}}

          not (is_integer(max) and max >= 1 and max <= 50_000_000) ->
            {:error, %InvalidOptionsError{message: "max_response_bytes is out of range"}}

          true ->
            {:ok, state.endpoint, timeout, max}
        end
      end

      defp do_post(endpoint, body, timeout, max) do
        request =
          Elixir.Req.Request.new(url: endpoint)
          |> Elixir.Req.Steps.attach()
          |> Elixir.Req.merge(
            # The fixed pool owns its connection settings. Req rejects a named
            # pool combined with connect_options; request_timeout still bounds
            # this request, and the client enforces the outer deadline.
            Keyword.delete(
              Triage.HTTP.options(timeout: timeout, max_bytes: max),
              :connect_options
            ) ++
              [headers: @fixed_headers, body: body, finch: [name: Elixir.Req.Finch]]
          )
          |> Map.put(:adapter, Elixir.Req.Finch)

        case Elixir.Req.post(request) do
          {:ok, response} -> finish(response, max)
          {:error, exception} -> {:error, transport_error(exception)}
        end
      end

      defp transport_error(exception) do
        message =
          if match?(%{__exception__: true}, exception) do
            Exception.message(exception)
          else
            "transport failed"
          end

        %TransportError{message: Errors.sanitize_message(message), reason: :transport}
      end

      defp finish(%{body: nil} = response, max), do: finish(%{response | body: ""}, max)

      defp finish(%{body: body} = response, max) do
        case Triage.HTTP.bounded_body(body, max) do
          {:ok, body} ->
            {:ok,
             %{status: response.status, headers: normalize_headers(response.headers), body: body}}

          {:error, :too_large} ->
            {:error,
             %ResponseBudgetError{message: "response exceeded the byte budget before decode"}}

          {:error, :invalid_body} ->
            {:error, %ResponseBudgetError{message: "response body was not a bounded binary"}}
        end
      end

      defp normalize_headers(headers) do
        Enum.reduce(headers, %{}, fn {key, values}, acc ->
          name = key |> to_string() |> String.downcase()

          if name in @dropped_headers do
            acc
          else
            Map.put(acc, name, List.first(List.wrap(values)) || "")
          end
        end)
      end
    end
  end
end
