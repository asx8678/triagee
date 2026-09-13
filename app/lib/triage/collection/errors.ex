defmodule Triage.Collection.Errors do
  @moduledoc """
  Terminal and transient error types for offline (read-only) collection.

  Every message is sanitized: it never contains credentials, cookies, bearer
  tokens, API keys, control characters, or a redirect `Location` value. A
  non-binary value is never inspected (inspection can echo secrets); it becomes
  a constant. Reasons are coerced to a closed set of atoms.
  """

  defmodule AuthError do
    @moduledoc "401/403 response: terminal authentication failure."
    @type t :: %__MODULE__{message: String.t() | nil, status: integer() | nil}
    defexception [:message, :status]
  end

  defmodule RedirectError do
    @moduledoc "3xx response. Redirects are never followed; Location is not echoed."
    @type t :: %__MODULE__{message: String.t() | nil, status: integer() | nil}
    defexception [:message, :status]
  end

  defmodule GraphQLError do
    @moduledoc "GraphQL-level error object or missing data. Terminal."
    @type t :: %__MODULE__{message: String.t() | nil}
    defexception [:message]
  end

  defmodule TransportError do
    @moduledoc "Transient transport failure that may be retried within bounds."
    @type t :: %__MODULE__{message: String.t() | nil, reason: atom() | nil}
    defexception [:message, :reason]
  end

  defmodule ResponseBudgetError do
    @moduledoc "Response exceeded the byte/depth budget before acceptance."
    @type t :: %__MODULE__{message: String.t() | nil}
    defexception [:message]
  end

  defmodule RequestBudgetError do
    @moduledoc "Request count/time budget exceeded."
    @type t :: %__MODULE__{message: String.t() | nil}
    defexception [:message]
  end

  defmodule CancelledError do
    @moduledoc "Collection was cancelled."
    @type t :: %__MODULE__{message: String.t() | nil}
    defexception [:message]
  end

  defmodule InvalidOptionsError do
    @moduledoc "Options failed validation before any network access."
    @type t :: %__MODULE__{message: String.t() | nil}
    defexception [:message]
  end

  defmodule DisabledError do
    @moduledoc "Offline entry: no live transport is configured."
    @type t :: %__MODULE__{message: String.t() | nil}
    defexception [:message]
  end

  @all [
    AuthError,
    RedirectError,
    GraphQLError,
    TransportError,
    ResponseBudgetError,
    RequestBudgetError,
    CancelledError,
    InvalidOptionsError,
    DisabledError
  ]

  @terminal [
    AuthError,
    RedirectError,
    GraphQLError,
    ResponseBudgetError,
    RequestBudgetError,
    CancelledError,
    InvalidOptionsError,
    DisabledError
  ]

  @safe_reasons [:transport, :status, :timeout, :worker, :cancelled, :decode, :budget]

  @doc "True when a struct is one of this module's collection errors."
  def collection_error?(%mod{}), do: mod in @all
  def collection_error?(_other), do: false

  @doc "True when an error is terminal and must never be retried."
  def terminal?(%mod{}), do: mod in @terminal
  def terminal?(_), do: false

  @doc """
  Sanitizes an error/message so credentials and redirect targets are never
  echoed. Credential-shaped values are removed, not merely relabelled. A
  non-binary, non-atom value becomes a constant; it is never inspected.
  """
  def sanitize_message(message) when is_binary(message) do
    message
    |> String.replace(~r/(?i)bearer\s+\S+/, "bearer <redacted>")
    |> String.replace(
      ~r/(?i)(cookie|authorization|proxy-authorization|token|secret|password|api[-_]?key)\s*[:=]\s*\S+/,
      "\\1=<redacted>"
    )
    |> String.replace(~r/[\x00-\x1F\x7F]/, "")
    |> String.slice(0, 400)
  end

  def sanitize_message(other) when is_atom(other),
    do: other |> Atom.to_string() |> sanitize_message()

  def sanitize_message(_other), do: "invalid message"

  @doc "Sanitizes the message of an exception without inspecting arbitrary terms."
  def sanitize_error(%{__exception__: true} = error) do
    %{error | message: sanitize_message(Exception.message(error))}
  end

  def sanitize_error(error), do: error

  @doc "Coerces a reason to a closed, non-leaking atom."
  def safe_reason(reason) when reason in @safe_reasons, do: reason
  def safe_reason(_other), do: :transport
end
