defmodule Triage.Reporting.Cursor do
  @moduledoc false

  @salt "reporting-api-v1"
  @max_age 86_400

  def encode(endpoint, filters, access, position) do
    Phoenix.Token.sign(TriageWeb.Endpoint, @salt, %{
      endpoint: endpoint,
      filters: Triage.Reporting.Filters.fingerprint(filters),
      grant: grant_fingerprint(access),
      position: position
    })
  end

  def decode(nil, _endpoint, _filters, _access), do: {:ok, nil}

  def decode(cursor, endpoint, filters, access) when is_binary(cursor) do
    with {:ok, payload} <-
           Phoenix.Token.verify(TriageWeb.Endpoint, @salt, cursor, max_age: @max_age),
         %{endpoint: ^endpoint, filters: expected, grant: grant, position: position} <- payload,
         true <- expected == Triage.Reporting.Filters.fingerprint(filters),
         true <- grant == grant_fingerprint(access) do
      {:ok, position}
    else
      _ ->
        {:error,
         %{
           status: 400,
           code: "invalid_cursor",
           detail: "Cursor is invalid for this endpoint, filter, or authorization scope"
         }}
    end
  end

  def decode(_cursor, _endpoint, _filters, _access),
    do: {:error, %{status: 400, code: "invalid_cursor", detail: "Cursor is invalid"}}

  defp grant_fingerprint(access) do
    :crypto.hash(:sha256, :erlang.term_to_binary({access.token_id, access.grants}))
  end
end
