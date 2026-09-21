defmodule TriageWeb.SessionHTML do
  use TriageWeb, :html

  def new(assigns) do
    ~H"""
    <Layouts.app flash={@flash}>
      <section aria-labelledby="login-heading">
        <h1 id="login-heading">Sign in</h1>
        <p>Accounts are provisioned by your administrator. Public registration is disabled.</p>
        <p :if={@error} id="login-error" role="alert">{@error}</p>
        <.form for={@form} id="login-form" action={~p"/login"} method="post">
          <.input
            field={@form[:email]}
            type="email"
            label="Email"
            autocomplete="username"
            required
            maxlength="120"
          />
          <.input
            field={@form[:password]}
            type="password"
            label="Password"
            autocomplete="current-password"
            required
            maxlength="1024"
          />
          <button id="login-submit" type="submit">Sign in</button>
        </.form>
      </section>
    </Layouts.app>
    """
  end
end
