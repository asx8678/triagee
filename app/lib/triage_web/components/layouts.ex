defmodule TriageWeb.Layouts do
  @moduledoc "Application shell: the workspace wrapper, flash notices and the account menu."
  use TriageWeb, :html

  # This tracked theme is edited directly, rather than produced by Tailwind.
  # Recompile the layout when it changes so ordinary reloads cannot reuse an old URL.
  @workspace_css_path Path.expand("../../../priv/static/assets/css/workspace.css", __DIR__)
  @external_resource @workspace_css_path
  @workspace_css_version Base.encode16(:crypto.hash(:sha256, File.read!(@workspace_css_path)),
                           case: :lower
                         )

  embed_templates "layouts/*"

  defp workspace_css_version, do: @workspace_css_version

  attr :flash, :map, required: true
  attr :current_scope, :map, default: nil
  slot :inner_block, required: true

  def app(assigns) do
    ~H"""
    <div class="approved-workspace">
      <.flash_group flash={@flash} />
      {render_slot(@inner_block)}
    </div>
    """
  end

  attr :current_scope, :map, default: nil

  def account(assigns) do
    ~H"""
    <div :if={@current_scope} id="account-menu" class="row wrap">
      <span id="verified-identity">{@current_scope.user.email} ({@current_scope.user.role})</span>
      <.form for={to_form(%{})} id="logout-form" action={~p"/logout"} method="delete">
        <button id="logout-button" type="submit">Sign out</button>
      </.form>
    </div>
    """
  end

  attr :flash, :map, required: true
  attr :id, :string, default: "flash-group"

  def flash_group(assigns) do
    ~H"""
    <div id={@id}>
      <div
        id="connection-notice"
        class="notice notice-error"
        role="status"
        hidden
        phx-disconnected={JS.remove_attribute("hidden", to: "#connection-notice")}
        phx-connected={JS.set_attribute({"hidden", ""}, to: "#connection-notice")}
      >
        <strong>Connection interrupted</strong>
        Check that the local service is running; the page reconnects by itself. Keep this tab open until it does, or your latest changes may be lost.
      </div>
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />
    </div>
    """
  end
end
