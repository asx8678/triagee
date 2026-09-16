defmodule Triage.Collection.Client do
  @signal_timeout_ms 100

  @moduledoc """
  Bounded GraphQL client over the fixed loopback transport.

  Terminal by construction:

    * 3xx redirects are never followed (`RedirectError`);
    * 401/403 are `AuthError`;
    * GraphQL error payloads (including malformed ones) and missing `data` are
      `GraphQLError`;
    * a returned body larger than the per-response byte budget, or a payload
      deeper than the depth budget, is a `ResponseBudgetError` even when a
      caller-injected transport skipped its own bound;
    * every admitted response body is charged, atomically and run-scoped,
      against the shared aggregate `max_total_bytes` budget BEFORE any JSON
      decode or retention; a response that would exceed the aggregate budget is
      rejected undecoded, no later request is admitted, and a late in-flight
      response fails closed;
    * request admission is an atomic reservation against the shared budget;
    * the remaining total deadline caps socket timeouts, retries and backoff;
    * the actual request runs in an unlinked, monitored worker; the caller polls
      cancellation/deadline while it is in flight and kills and drains its own
      worker on cancellation or deadline expiry, so an in-flight request is
      interrupted rather than awaited.

  Errors are sanitized constants: raw transport reasons and payloads are never
  echoed into messages or `:reason`, reasons are coerced to a closed atom set,
  and signal callbacks run in monitored, unlinked processes bounded by
  `min(remaining deadline, #{@signal_timeout_ms} ms)` so a stall cannot outlive the deadline or
  leak arguments into OTP logs.

  Bounded in-flight overhead: responses already accepted by the transport may
  still be in flight when the aggregate budget is exhausted. At most
  `concurrency` requests are in flight and the transport caps each body at
  `max_response_bytes`, so at most `concurrency * max_response_bytes` extra
  bytes may be transmitted before those late responses are rejected; those bytes
  are never decoded or retained, and the transport streams and halts at its
  per-response cap.
  """

  alias Triage.Collection.Errors, as: E

  alias Triage.Collection.Errors.{
    AuthError,
    GraphQLError,
    InvalidOptionsError,
    RedirectError,
    TransportError
  }

  defstruct [:config, :transport, :transport_state, :deadline, :signal, :counter, :budget, :error]

  @doc "Builds a shared client. The counter/budget/deadline are shared across workers."
  def new(config, transport, transport_state, opts) do
    with {:ok, signal} <- validate_new_opts(opts),
         {:ok, config} <- Triage.Collection.Config.revalidate(config) do
      %__MODULE__{
        config: config,
        transport: transport,
        transport_state: transport_state,
        deadline: now() + config.total_deadline_ms,
        signal: signal,
        counter: :atomics.new(1, signed: false),
        budget: :atomics.new(2, signed: false),
        error: consistency_error(transport, config, transport_state)
      }
    else
      {:error, error} ->
        # A forged/invalid config or malformed options never reaches the transport.
        %__MODULE__{
          config: config,
          transport: transport,
          transport_state: transport_state,
          deadline: now() + 1,
          signal: nil,
          counter: :atomics.new(1, signed: false),
          budget: :atomics.new(2, signed: false),
          error: error
        }
    end
  end

  @doc "Number of reservations taken so far (including retries)."
  def request_count(%__MODULE__{counter: counter}), do: :atomics.get(counter, 1)

  @doc "Milliseconds remaining before the total deadline (may be negative)."
  def remaining_ms(%__MODULE__{deadline: deadline}), do: deadline - now()

  @doc "True when cancellation is requested. A stalling callback is treated as cancelled."
  def cancelled?(%__MODULE__{signal: nil}), do: false

  def cancelled?(%__MODULE__{signal: fun} = client) when is_function(fun, 0),
    do: signal_cancelled?(client, fun)

  def cancelled?(_other), do: false

  @doc "Runs one GraphQL query. Returns `{:ok, data}` or `{:error, exception}`."
  def query(%__MODULE__{} = client, query_string, label) do
    case client.error do
      nil ->
        with :ok <- validate_client(client) do
          attempt(client, query_string, label, 0)
        end

      error ->
        # A stored (possibly forged) error is coerced to a controlled, sanitized
        # error and no transport call is made.
        {:error, controlled_error(error)}
    end
  end

  def query(_other, _query_string, _label) do
    {:error, %InvalidOptionsError{message: "client must be a validated Client struct"}}
  end

  # A forged or corrupted client is rejected before any transport call: the
  # config, transport, atomics refs and transport state are all revalidated.
  defp validate_client(%__MODULE__{} = client) do
    cond do
      not match?(%Triage.Collection.Config{}, client.config) ->
        invalid_client()

      not is_atom(client.transport) ->
        invalid_client()

      not valid_atomics?(client.counter) ->
        invalid_client()

      not valid_budget?(client.budget) ->
        invalid_client()

      match?({:error, _}, Triage.Collection.Config.revalidate(client.config)) ->
        invalid_client()

      true ->
        case consistency_error(client.transport, client.config, client.transport_state) do
          nil -> :ok
          %_{} = error -> {:error, controlled_error(error)}
        end
    end
  end

  defp invalid_client, do: {:error, %InvalidOptionsError{message: "client state is invalid"}}

  # `:atomics.get/2` takes an opaque reference, so dialyzer can prove that a
  # plain reference — exactly the forged input these two probes exist to reject —
  # always fails the call. That proof would make every branch after a valid
  # client look unreachable, which is what it does today: the whole retry,
  # budget and transport path reads as dead code to dialyzer. Dispatching
  # through a value keeps the failure a runtime result, which is the case the
  # rescue below handles, and the forged-client regressions in
  # test/triage/collection/residual_test.exs still exercise it.
  @atomics :atomics

  defp atomics_get(ref, slot), do: apply(@atomics, :get, [ref, slot])

  defp valid_atomics?(ref) when is_reference(ref) do
    _ = atomics_get(ref, 1)
    true
  rescue
    _ -> false
  end

  defp valid_atomics?(_other), do: false

  # The aggregate budget is a 2-slot atomics (1 = bytes charged, 2 = exhausted
  # flag). A forged reference of the wrong size must be rejected here instead
  # of raising from a later slot read.
  defp valid_budget?(ref) when is_reference(ref) do
    _ = atomics_get(ref, 1)
    _ = atomics_get(ref, 2)
    true
  rescue
    _ -> false
  end

  defp valid_budget?(_other), do: false

  defp controlled_error(%{__exception__: true} = error), do: normalize_transport_error(error)

  defp controlled_error(_other),
    do: %TransportError{message: "client state is invalid", reason: :worker}

  defp validate_new_opts(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      validate_signal_opt(Keyword.get(opts, :signal))
    else
      {:error, %InvalidOptionsError{message: "client options must be a keyword list"}}
    end
  end

  defp validate_new_opts(opts) when is_map(opts), do: validate_new_opts(Map.to_list(opts))

  defp validate_new_opts(_other) do
    {:error, %InvalidOptionsError{message: "client options must be a keyword list"}}
  end

  defp validate_signal_opt(nil), do: {:ok, nil}
  defp validate_signal_opt(fun) when is_function(fun, 0), do: {:ok, fun}

  defp validate_signal_opt(_other) do
    {:error, %InvalidOptionsError{message: "signal must be a zero-arity function"}}
  end

  defp consistency_error(transport, config, state) do
    if transport == Triage.Collection.Transport.Req do
      cond do
        not is_map(state) ->
          %InvalidOptionsError{message: "transport state must be a struct"}

        Map.get(state, :endpoint) != config.endpoint ->
          %InvalidOptionsError{
            message: "transport state endpoint does not match the validated config"
          }

        Map.get(state, :request_timeout_ms) != config.request_timeout_ms ->
          %InvalidOptionsError{
            message: "transport state timeout does not match the validated config"
          }

        Map.get(state, :max_response_bytes) != config.max_response_bytes ->
          %InvalidOptionsError{
            message: "transport state byte budget does not match the validated config"
          }

        true ->
          nil
      end
    end
  end

  defp attempt(client, query, label, attempt_no) do
    with :ok <- preflight(client),
         :ok <- reserve(client) do
      remaining = remaining_ms(client)

      case do_attempt(client, query, label, remaining) do
        {:ok, data} ->
          case post_check(client) do
            :ok -> {:ok, data}
            {:error, error} -> {:error, error}
          end

        {:error, error} ->
          maybe_retry(client, query, label, attempt_no, error)
      end
    end
  end

  defp preflight(client) do
    cond do
      cancelled?(client) ->
        {:error, %E.CancelledError{message: "collection cancelled"}}

      deadline_passed?(client) ->
        {:error, %E.RequestBudgetError{message: "collection deadline exceeded"}}

      true ->
        :ok
    end
  end

  defp reserve(client) do
    reserved = :atomics.add_get(client.counter, 1, 1)

    cond do
      reserved > client.config.max_requests ->
        {:error, %E.RequestBudgetError{message: "request budget exhausted"}}

      budget_exhausted?(client) ->
        {:error, budget_error()}

      true ->
        :ok
    end
  end

  # Run-scoped atomic aggregate response-byte admission. The byte total lives in
  # a shared atomics slot so concurrent detail workers cannot overshoot: the
  # check-and-add is a compare-and-exchange loop, and a response that would push
  # the total past `max_total_bytes` is rejected before decode/retention. Once
  # the budget is exhausted the flag makes later and late responses fail closed.
  defp charge_response_bytes(client, bytes) when is_integer(bytes) and bytes >= 0 do
    if budget_exhausted?(client) do
      {:error, budget_error()}
    else
      reserve_bytes(client, bytes)
    end
  end

  defp reserve_bytes(client, bytes) do
    ref = client.budget
    max = client.config.max_total_bytes
    current = :atomics.get(ref, 1)

    if current + bytes > max do
      :atomics.put(ref, 2, 1)
      {:error, budget_error()}
    else
      case :atomics.compare_exchange(ref, 1, current, current + bytes) do
        :ok -> :ok
        _actual -> reserve_bytes(client, bytes)
      end
    end
  end

  defp budget_exhausted?(client) do
    is_reference(client.budget) and :atomics.get(client.budget, 2) == 1
  end

  defp budget_error do
    %E.ResponseBudgetError{message: "aggregate response byte budget exceeded before decode"}
  end

  defp post_check(client) do
    cond do
      cancelled?(client) ->
        {:error, %E.CancelledError{message: "collection cancelled"}}

      deadline_passed?(client) ->
        {:error, %E.RequestBudgetError{message: "collection deadline exceeded"}}

      true ->
        :ok
    end
  end

  defp do_attempt(client, query, label, remaining) do
    body = Jason.encode!(%{query: query})

    timeout =
      client.config.request_timeout_ms
      |> min(max(remaining, 1))
      |> max(1)

    opts = [
      receive_timeout: timeout,
      deadline_ms: remaining,
      max_response_bytes: client.config.max_response_bytes
    ]

    run_transport_worker(client, body, opts, remaining, label)
  end

  # The request runs in an unlinked, monitored worker. Exceptions are caught
  # inside the worker so a raised payload can never reach OTP logs, and the
  # caller only ever sees a constant classification.
  defp run_transport_worker(client, body, opts, remaining, label) do
    parent = self()

    {pid, ref} =
      spawn_monitor(fn ->
        result =
          try do
            client.transport.post(client.transport_state, body, opts)
          rescue
            _ -> {:raised, :transport}
          catch
            _kind, _reason -> {:caught, :transport}
          end

        send(parent, {:__collection_transport__, self(), result})
      end)

    poll_transport(client, label, pid, ref, now() + max(remaining, 0))
  end

  defp poll_transport(client, label, pid, ref, deadline) do
    slice = min(50, max(deadline - now(), 0))

    receive do
      {:__collection_transport__, ^pid, result} ->
        Process.demonitor(ref, [:flush])
        handle_transport(client, result, label)

      {:DOWN, ^ref, :process, ^pid, _reason} ->
        drain_result(client, label, pid)
    after
      slice ->
        cond do
          cancelled?(client) ->
            kill_worker(pid, ref)
            {:error, %E.CancelledError{message: "collection cancelled"}}

          now() >= deadline ->
            kill_worker(pid, ref)
            {:error, %E.RequestBudgetError{message: "collection deadline exceeded"}}

          true ->
            poll_transport(client, label, pid, ref, deadline)
        end
    end
  end

  # A worker may send its result and exit; the result signal is ordered before
  # the DOWN, but drain the mailbox defensively before treating it as a crash.
  defp drain_result(client, label, pid) do
    receive do
      {:__collection_transport__, ^pid, result} -> handle_transport(client, result, label)
    after
      0 -> {:error, %TransportError{message: "transport worker exited", reason: :worker}}
    end
  end

  defp kill_worker(pid, ref) do
    Process.demonitor(ref, [:flush])
    Process.exit(pid, :kill)
    drain_all(pid)
  end

  defp drain_all(pid) do
    receive do
      {:__collection_transport__, ^pid, _} -> drain_all(pid)
      {:__collection_signal__, ^pid, _} -> drain_all(pid)
      {:DOWN, _, :process, ^pid, _} -> drain_all(pid)
    after
      0 -> :ok
    end
  end

  defp handle_transport(client, {:ok, %{status: status} = response}, label)
       when is_integer(status) do
    case Map.get(response, :body) do
      response_body when is_binary(response_body) ->
        admit_response(client, status, response_body, label)

      nil ->
        admit_response(client, status, "", label)

      _other ->
        {:error,
         %TransportError{message: "transport returned a non-binary body", reason: :transport}}
    end
  end

  defp handle_transport(_client, {:ok, _other}, _label) do
    {:error,
     %TransportError{message: "transport returned an invalid response", reason: :transport}}
  end

  defp handle_transport(_client, {:error, error}, _label) do
    {:error, normalize_transport_error(error)}
  end

  defp handle_transport(_client, _other, _label) do
    {:error, %TransportError{message: "transport failed", reason: :transport}}
  end

  # The response is charged against the aggregate budget before any decode, so a
  # body that would push the run past `max_total_bytes` is never decoded or
  # retained and no later request is admitted.
  defp admit_response(client, status, body, label) do
    if byte_size(body) > client.config.max_response_bytes do
      {:error, %E.ResponseBudgetError{message: "response exceeded the byte budget"}}
    else
      case charge_response_bytes(client, byte_size(body)) do
        :ok -> classify_response(client, status, body, label)
        {:error, error} -> {:error, error}
      end
    end
  end

  defp classify_response(client, status, body, label) do
    cond do
      status >= 300 and status < 400 ->
        {:error,
         %RedirectError{message: "redirect (HTTP #{status}) is not followed", status: status}}

      status in [401, 403] ->
        {:error, %AuthError{message: "authentication failed (HTTP #{status})", status: status}}

      status >= 200 and status < 300 ->
        decode(client, body, label)

      status in client.config.retry_statuses ->
        {:error, %TransportError{message: "#{label}: HTTP #{status}", reason: :status}}

      true ->
        {:error, %GraphQLError{message: "#{label}: HTTP #{status}"}}
    end
  end

  defp decode(client, body, label) do
    case Jason.decode(body) do
      {:ok, %{"errors" => errors} = payload} ->
        if is_list(errors) and errors == [] and is_map(payload["data"]) do
          bounded(client, payload["data"], label)
        else
          {:error, %GraphQLError{message: "#{label}: GraphQL error payload"}}
        end

      {:ok, %{"data" => data}} when is_map(data) ->
        bounded(client, data, label)

      {:ok, _other} ->
        {:error, %GraphQLError{message: "#{label}: response contained no data"}}

      {:error, _reason} ->
        {:error, %GraphQLError{message: "#{label}: response was not valid JSON"}}
    end
  end

  defp bounded(client, data, label) do
    if depth_exceeds?(data, client.config.max_payload_depth, 0) do
      {:error, %E.ResponseBudgetError{message: "#{label}: response exceeded the depth budget"}}
    else
      {:ok, data}
    end
  end

  defp depth_exceeds?(_value, max, level) when level > max, do: true

  defp depth_exceeds?(value, max, level) when is_map(value) do
    Enum.any?(value, fn {_key, nested} -> depth_exceeds?(nested, max, level + 1) end)
  end

  defp depth_exceeds?(value, max, level) when is_list(value) do
    Enum.any?(value, &depth_exceeds?(&1, max, level + 1))
  end

  defp depth_exceeds?(_value, _max, _level), do: false

  defp normalize_transport_error(%{__exception__: true} = error) do
    if E.collection_error?(error) do
      sanitized =
        Map.put(error, :message, E.sanitize_message(Map.get(error, :message, "transport error")))

      if Map.has_key?(error, :reason) do
        Map.put(sanitized, :reason, E.safe_reason(Map.get(error, :reason)))
      else
        sanitized
      end
    else
      %TransportError{message: E.sanitize_message(Exception.message(error)), reason: :transport}
    end
  end

  # A transport may fail with something that is not an exception at all: the
  # injected transports in test/triage/collection/client_test.exs return raw
  # tuples that can carry credentials, and that shape must be coerced to a
  # sanitized TransportError rather than passed through. Dialyzer cannot see
  # those callers — test files are `.exs` and are not part of its analysis — so
  # it concludes this clause can never match and reports the coverage warning
  # silenced below. The behaviour it implements is asserted in that test file.
  @dialyzer {:nowarn_function, normalize_transport_error: 1}

  defp normalize_transport_error(_other) do
    %TransportError{message: "transport failed", reason: :transport}
  end

  defp maybe_retry(client, query, label, attempt_no, error) do
    if E.terminal?(error) or attempt_no >= client.config.max_retries do
      {:error, with_attempts(error, attempt_no + 1, label)}
    else
      delay = min(200 * Integer.pow(2, attempt_no), 2_000)

      case interruptible_wait(client, delay) do
        :ok -> attempt(client, query, label, attempt_no + 1)
        {:error, wait_error} -> {:error, wait_error}
      end
    end
  end

  defp interruptible_wait(client, delay) do
    wait_until(client, now() + delay)
  end

  defp wait_until(client, deadline) do
    cond do
      cancelled?(client) ->
        {:error, %E.CancelledError{message: "collection cancelled"}}

      deadline_passed?(client) ->
        {:error, %E.RequestBudgetError{message: "collection deadline exceeded"}}

      now() >= deadline ->
        :ok

      true ->
        Process.sleep(min(50, deadline - now()))
        wait_until(client, deadline)
    end
  end

  defp signal_cancelled?(client, fun) do
    # A stalling, crashing or ill-behaved callback means "not proven live". It
    # runs in a monitored, unlinked worker bounded by the remaining deadline (or
    # a small fixed budget, whichever is smaller), so it can never outlive the
    # deadline nor take down the caller. Its exception message is never logged
    # or echoed.
    timeout =
      client
      |> remaining_ms()
      |> min(@signal_timeout_ms)
      |> max(0)

    parent = self()

    {pid, ref} =
      spawn_monitor(fn ->
        result =
          try do
            {:ok, fun.()}
          rescue
            _ -> :invalid
          catch
            _kind, _reason -> :invalid
          end

        send(parent, {:__collection_signal__, self(), result})
      end)

    receive do
      {:__collection_signal__, ^pid, {:ok, value}} ->
        Process.demonitor(ref, [:flush])
        value not in [false, nil]

      {:__collection_signal__, ^pid, :invalid} ->
        Process.demonitor(ref, [:flush])
        true

      {:DOWN, ^ref, :process, ^pid, _reason} ->
        true
    after
      timeout ->
        Process.demonitor(ref, [:flush])
        Process.exit(pid, :kill)
        drain_all(pid)
        true
    end
  end

  defp with_attempts(error, attempts, label) do
    if attempts > 1 and not E.terminal?(error) and match?(%{message: _}, error) do
      sanitized = E.sanitize_message(Map.get(error, :message, ""))
      %{error | message: "#{label}: failed after #{attempts} attempts (#{sanitized})"}
    else
      error
    end
  end

  defp deadline_passed?(%__MODULE__{deadline: deadline}), do: now() >= deadline

  defp now, do: System.monotonic_time(:millisecond)
end
