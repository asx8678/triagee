defmodule TriageWeb.SessionHTMLTest do
  use TriageWeb.ConnCase, async: true

  test "public sign-in uses the loaded workspace theme without retired navigation", %{conn: conn} do
    document = conn |> get(~p"/login") |> login_document(200)

    assert Enum.count(LazyHTML.query(document, ".auth-header img.auth-logo[width='240']")) == 1
    assert Enum.count(LazyHTML.query(document, ".skip-link[href='#main-content']")) == 1
    assert Enum.empty?(LazyHTML.query(document, "#primary-navigation, .triage-topbar"))
    assert Enum.empty?(LazyHTML.query(document, "#login-error"))
    assert LazyHTML.text(LazyHTML.query(document, "title")) =~ "Sign in"
  end

  test "failed sign-in retains the themed form and accessible generic error", %{conn: conn} do
    document = conn |> post(~p"/login", %{}) |> login_document(401)

    assert Enum.count(LazyHTML.query(document, "#login-error.auth-error[role='alert']")) == 1

    assert LazyHTML.text(LazyHTML.query(document, "#login-error")) ==
             "Invalid email or password."

    assert Enum.count(
             LazyHTML.query(document, "#login-form[aria-describedby='login-error login-help']")
           ) == 1
  end

  defp login_document(conn, status) do
    document = conn |> html_response(status) |> LazyHTML.from_document()

    assert Enum.count(
             LazyHTML.query(document, ".approved-workspace #login-page.auth-shell #login-panel")
           ) == 1

    for selector <- [
          "#main-content.auth-main",
          "#login-form[action='/login'][method='post']",
          "#login-form input[type='hidden'][name='_csrf_token'][value]",
          "#login-form label[for='session_email']",
          "#session_email[type='email'][autocomplete='username'][required]",
          "#login-form label[for='session_password']",
          "#session_password[type='password'][autocomplete='current-password'][required]",
          "#login-submit.primary[type='submit']",
          "#login-help"
        ] do
      assert Enum.count(LazyHTML.query(document, selector)) == 1, selector
    end

    hrefs =
      document
      |> LazyHTML.query("link[rel=stylesheet]")
      |> Enum.flat_map(&LazyHTML.attribute(&1, "href"))

    assert ["/assets/css/tailwind.css", theme_href] = hrefs
    theme_uri = URI.parse(theme_href)
    assert theme_uri.path == "/assets/css/workspace.css"

    version =
      :crypto.hash(:sha256, File.read!("priv/static/assets/css/workspace.css"))
      |> Base.encode16(case: :lower)

    assert URI.decode_query(theme_uri.query) == %{"v" => version}
    document
  end
end
