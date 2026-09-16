defmodule TriageWeb.ReferenceComponents do
  @moduledoc "Truthful provenance for public NVD records shown through the triage workflow."
  use TriageWeb, :html
  alias Triage.ReferenceData

  attr :id, :string, required: true
  attr :finding, :map, default: nil

  def reference_notice(assigns) do
    assigns =
      assign(
        assigns,
        :reference?,
        not is_nil(assigns.finding) and ReferenceData.reference_image?(assigns.finding.image)
      )

    ~H"""
    <section
      :if={@reference?}
      id={@id}
      class="notice stack"
      aria-label="Real NVD reference provenance"
    >
      <h2>Real CVE · public NVD reference data</h2>
      <p>{ReferenceData.warning()}</p>
      <p class="supporting">{@finding.image.description}</p>
      <.link
        id={@id <> "-link"}
        href={"https://nvd.nist.gov/vuln/detail/" <> URI.encode(@finding.cve)}
        target="_blank"
        rel="noopener noreferrer"
      >Read the original NVD advisory</.link>
      <details id={@id <> "-details"} class="disclosure">
        <summary>NVD description, CVSS score and affected-product evidence</summary>
        <p style="white-space: pre-wrap; overflow-wrap: anywhere;">{@finding.description}</p>
      </details>
    </section>
    """
  end
end
