defmodule TriageWeb.SessionHTML do
  use TriageWeb, :html

  def new(assigns) do
    ~H"""
    <Layouts.app flash={@flash} workspace={true}>
      <div id="login-page" class="auth-shell">
        <a href="#main-content" class="skip-link">Skip to sign in</a>
        <header class="auth-header">
          <img
            src={~p"/images/triage-wordmark-v2.png"}
            width="240"
            height="35"
            class="auth-logo"
            alt="PTV Triage"
          />
        </header>
        <main id="main-content" class="auth-main" tabindex="-1">
          <section id="login-panel" class="panel auth-panel" aria-labelledby="login-heading">
            <div class="auth-intro">
              <p class="auth-eyebrow">Vulnerability review</p>
              <h1 id="login-heading">Sign in</h1>
              <p class="muted">Use your administrator-provided account to continue.</p>
            </div>
            <p :if={@error} id="login-error" class="auth-error" role="alert">{@error}</p>
            <.form
              for={@form}
              id="login-form"
              action={~p"/login"}
              method="post"
              aria-describedby={if @error, do: "login-error login-help", else: "login-help"}
            >
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
              <button id="login-submit" class="primary auth-submit" type="submit">Sign in</button>
            </.form>
            <div :if={@skip_login?} class="auth-skip">
              <.form for={to_form(%{})} id="login-skip-form" action={~p"/login/skip"} method="post">
                <button id="login-skip" class="quiet" type="submit" aria-describedby="login-skip-note">
                  Skip
                </button>
              </.form>
              <span id="login-skip-note" class="muted">Continue as local user</span>
            </div>
            <p id="login-help" class="auth-help muted">
              Accounts are provisioned by your administrator. Public registration is disabled.
            </p>
          </section>
        </main>
        <footer class="auth-footer">PTV Triage · Authorized access only</footer>
      </div>
    </Layouts.app>
    """
  end
end
