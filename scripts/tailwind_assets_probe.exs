# DB-free verification of the Tailwind asset wiring.
#
# Run from app/:  mise x -- mix run ../scripts/tailwind_assets_probe.exs
#
# The same properties are asserted by test/triage_web/assets_test.exs, but that
# case uses TriageWeb.ConnCase and therefore needs PostgreSQL. This probe needs
# no database, so the asset pipeline can be checked on a host without one. It
# checks the real files (green) and then in-memory mutants (red), so each
# assertion is shown to catch the defect it claims to.
#
# Exit status is 0 only when every check passes.

tailwind_source = "assets/css/tailwind.css"
tailwind_output = "priv/static/assets/css/tailwind.css"
application_stylesheet = "priv/static/assets/css/app.css"

get = fn path ->
  conn = Plug.Test.conn(:get, path) |> TriageWeb.Endpoint.call([])
  {conn.status, conn.resp_body}
end

{_, html} = get.("/")

hrefs =
  Regex.scan(~r{<link\b[^>]*>}, html)
  |> List.flatten()
  |> Enum.filter(&(&1 =~ "stylesheet"))
  |> Enum.map(fn tag ->
    Regex.run(~r{href="([^"]+)"}, tag, capture: :all_but_first) |> List.first()
  end)

source = File.read!(tailwind_source)
live_source = Regex.replace(~r{/\*.*?\*/}s, source, "")
built = File.read!(tailwind_output)
{200, served_tailwind} = get.("/assets/css/tailwind.css")
{200, served_app} = get.("/assets/css/app.css")

css = served_tailwind <> served_app
live_css = Regex.replace(~r{/\*.*?\*/}s, css, "")

icons =
  "lib/**/*.{ex,heex,eex}"
  |> Path.wildcard()
  |> Enum.flat_map(fn path ->
    ~r/name="(hero-[a-z0-9-]+)"/
    |> Regex.scan(File.read!(path), capture: :all_but_first)
    |> List.flatten()
  end)
  |> Enum.uniq()

artwork? = fn text, icon ->
  Regex.match?(
    ~r/\.#{Regex.escape(icon)}\s*\{[^}]*\bmask-image:\s*url\(['"]?data:image\/svg\+xml;/s,
    text
  )
end

lib_sources =
  Path.wildcard("lib/**/*.{ex,heex,eex}") |> Enum.map(&File.read!/1) |> Enum.join("\n")

stripped_art =
  Regex.replace(~r/^\.hero-(?:arrow-path|exclamation-circle|x-mark) \{[^}]*\}$/m, live_css, "")

extra_source = live_source <> "\n@source \"../../deps\";\n"

commented =
  Regex.replace(
    ~r{@import "tailwindcss" source\(none\);},
    source,
    "/* @import \"tailwindcss\" source(none); */"
  )

commented_live = Regex.replace(~r{/\*.*?\*/}s, commented, "")

# Both builds write only under a fresh temporary tree, never into the repository.
cli = Path.expand("_build/tailwind-linux-x64-4.1.18")
temp = Path.join(System.tmp_dir!(), "tailwind-assets-probe-" <> Base.encode16(:crypto.strong_rand_bytes(16)))
File.mkdir!(temp)

{reproduced, clean_generated, template_scanned, witness_absent_from_clean} =
  try do
    assets = Path.join(temp, "assets")
    File.mkdir_p!(Path.join(assets, "css"))
    File.cp!(tailwind_source, Path.join(assets, "css/tailwind.css"))
    # Copy lib so ../../lib resolves inside this tree without symlink traversal.
    File.cp_r!("lib", Path.join(temp, "lib"))

    run = fn output ->
      System.cmd(cli, ["--input=css/tailwind.css", "--output=#{output}"],
        cd: assets,
        stderr_to_stdout: true
      )
    end

    # Preserve the existing rebuild check, but seed a temporary destination.
    rebuild_output = Path.join(temp, "rebuild.css")
    before = File.read!(tailwind_output)
    File.write!(rebuild_output, before)
    {_, rebuild_status} = run.(rebuild_output)
    reproduced = rebuild_status == 0 and File.read!(rebuild_output) == before

    # out.css has never existed: this checks clean generation, not an overwrite.
    fresh_output = Path.join(temp, "out.css")
    {_, fresh_status} = run.(fresh_output)
    expected_sha256 = :crypto.hash(:sha256, File.read!(tailwind_output))

    clean_generated =
      fresh_status == 0 and
        case File.read(fresh_output) do
          {:ok, bytes} -> :crypto.hash(:sha256, bytes) == expected_sha256
          {:error, _} -> false
        end

    # No repository utility class is used only by a template, so the template
    # scan is witnessed synthetically: a .heex file added to this temporary
    # lib copy carries one arbitrary utility that appears nowhere in the
    # repository. If the scan skipped templates the class would not be
    # emitted; 37px is this witness's own value, so nothing else can emit it.
    File.write!(
      Path.join([temp, "lib", "triage_web", "probe_scan_witness.html.heex"]),
      ~s(<div class="w-[37px]">template scan witness</div>\n)
    )

    witness_output = Path.join(temp, "witness.css")
    {_, witness_status} = run.(witness_output)

    witness_bytes =
      case File.read(witness_output) do
        {:ok, bytes} -> bytes
        {:error, _} -> ""
      end

    witness_absent_from_clean = not String.contains?(File.read!(fresh_output), "37px")

    template_scanned =
      witness_status == 0 and String.contains?(witness_bytes, "37px") and
        witness_absent_from_clean and not String.contains?(File.read!(tailwind_output), "37px")

    {reproduced, clean_generated, template_scanned, witness_absent_from_clean}
  after
    File.rm_rf!(temp)
  end

checks = [
  {"green order tailwind-before-app",
   hrefs == ["/assets/css/tailwind.css", "/assets/css/app.css"]},
  {"green same-origin", Enum.all?(hrefs, &String.starts_with?(&1, "/"))},
  {"green served tailwind == file bytes", served_tailwind == built},
  {"green served app.css == file bytes", served_app == File.read!(application_stylesheet)},
  {"green v4 banner", served_tailwind =~ "tailwindcss v4"},
  {"green theme --color-error", served_tailwind =~ "--color-error: #a02222"},
  {"green theme --color-base-content", served_tailwind =~ "--color-base-content: #182539"},
  {"green utility .size-5", served_tailwind =~ ".size-5 {"},
  {"green utility .w-full", served_tailwind =~ ".w-full {"},
  {"green scan source(none) live", live_source =~ ~s{@import "tailwindcss" source(none)}},
  {"green scan exactly one @source -> lib",
   Regex.scan(~r/@source\b[^;]*;/, live_source) == [[~s{@source "../../lib";}]]},
  {"green reproducible rebuild", reproduced},
  {"green clean generation sha256 matches shipped CSS", clean_generated},
  {"green .heex template scan witness is emitted", template_scanned},
  {"green icons found", icons != []},
  {"green every icon has artwork", Enum.all?(icons, &artwork?.(live_css, &1))}
]

mutants = [
  {"red artwork regex rejects per-icon-rule removal",
   not Enum.all?(icons, &artwork?.(stripped_art, &1))},
  {"red old name-only check still passes (weakness was real)",
   Enum.all?(icons, fn i -> stripped_art =~ ".#{i}" end)},
  {"red extra @source fails scan assertion",
   Regex.scan(~r/@source\b[^;]*;/, extra_source) != [[~s{@source "../../lib";}]]},
  {"red commented-out directive fails live scan",
   not (commented_live =~ ~s{@import "tailwindcss" source(none)})},
  {"red .grid witness was incidental (no class=grid in lib)",
   not (lib_sources =~ "class=\"grid\"")},
  # The witness class exists only because the temporary tree has the template:
  # the same CLI, run without it, must not emit 37px.
  {"red witness class absent without the template", witness_absent_from_clean}
]

report = fn label, ok -> IO.puts(if(ok, do: "PASS", else: "FAIL") <> "  " <> label) end
Enum.each(checks, fn {l, ok} -> report.(l, ok) end)
Enum.each(mutants, fn {l, ok} -> report.(l, ok) end)

failed = Enum.count(checks ++ mutants, fn {_, ok} -> not ok end)
IO.puts("icons=#{inspect(icons)}")
IO.puts("SUMMARY green=#{length(checks)} red=#{length(mutants)} failed=#{failed}")
if failed > 0, do: System.halt(1)
