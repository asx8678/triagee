defmodule Triage.IntelClientTest do
  use ExUnit.Case, async: true

  alias Triage.Intel.Client

  defp transport(body), do: %{req: fn _url -> {:ok, %{status: 200, body: body}} end}
  defp kev_body(entries), do: Jason.encode!(%{"vulnerabilities" => entries})

  test "the whole KEV feed is cached, never a prefix of it" do
    # A truncated cache makes "no cached KEV entry" appear for advisories that are
    # in CISA's catalogue, so the row count must follow the feed.
    entries =
      for n <- 1..80 do
        %{
          "cveID" => "CVE-2026-#{1000 + n}",
          "shortDescription" => "advisory #{n}",
          "dateAdded" => "2026-01-02"
        }
      end

    assert {:ok, rows} = Client.fetch(:kev, transport(kev_body(entries)))
    assert length(rows) == 80
    assert List.first(rows).external_id == "CVE-2026-1001"
    assert List.last(rows).external_id == "CVE-2026-1080"
  end

  test "KEV actionability is captured: required action, due date, ransomware use" do
    entries = [
      %{
        "cveID" => "CVE-2026-2001",
        "shortDescription" => "exploited, ransomware-linked",
        "dateAdded" => "2026-01-02",
        "requiredAction" => "Apply updates per vendor instructions.",
        "dueDate" => "2026-01-23",
        "knownRansomwareCampaignUse" => "Known"
      },
      %{
        "cveID" => "CVE-2026-2002",
        "shortDescription" => "no action fields",
        "dateAdded" => "2026-02-02",
        "knownRansomwareCampaignUse" => "Unknown"
      }
    ]

    assert {:ok, [a, b]} = Client.fetch(:kev, transport(kev_body(entries)))

    assert a.required_action == "Apply updates per vendor instructions."
    assert a.due_date == ~U[2026-01-23 00:00:00Z]
    assert a.known_ransomware == true

    # "Unknown" is CISA's own statement and a missing field is unknown: neither is a
    # reassuring false, and both stay nil/false rather than becoming "verified safe".
    assert b.known_ransomware == false
    assert b.required_action == nil
    assert b.due_date == nil
  end

  test "hostile KEV text is reduced to plain text before it is cached" do
    entries = [
      %{
        "cveID" => "CVE-2026-3001",
        "dateAdded" => "2026-03-03",
        "shortDescription" => "<img src=x onerror=alert(1)>\u0000",
        "requiredAction" => "Patch\u0000now"
      }
    ]

    assert {:ok, [row]} = Client.fetch(:kev, transport(kev_body(entries)))
    assert row.summary == "<img src=x onerror=alert(1)>"
    assert row.required_action == "Patch now"
  end

  test "an oversized response is refused for every transport, never truncated" do
    # The bound is enforced in one place for injected fakes and the real transport
    # alike, so no oversized body can reach a parser.
    oversize = :binary.copy("x", 8_000_001)

    assert Client.fetch(:kev, transport(oversize)) == {:error, {:response_too_large, 8_000_000}}
  end

  test "a transport result is interpreted in one place for fakes and the real client" do
    # Same vocabulary the real transport produces, so a fake cannot smuggle a body
    # past a non-200 status or a redirect.
    assert Client.fetch(:kev, %{req: fn _url -> {:ok, %{status: 500, body: "{}"}} end}) ==
             {:error, {:http_status, 500}}

    assert Client.fetch(:kev, %{req: fn _url -> {:ok, %{status: 302, body: "{}"}} end}) ==
             {:error, {:redirect_refused, 302}}

    assert Client.fetch(:kev, %{req: fn _url -> {:error, :intel_disabled} end}) ==
             {:error, :intel_disabled}

    assert Client.fetch(:kev, %{req: fn _url -> :nonsense end}) ==
             {:error, :unexpected_transport_result}

    assert Client.fetch(:kev, %{}) == {:error, :no_transport}
  end

  test "malformed KEV records reject the whole feed, never a partial or empty success" do
    valid = %{"cveID" => "CVE-2026-2001"}

    invalid = [
      nil,
      true,
      "not a record",
      [],
      %{},
      %{"cveID" => nil},
      %{"cveID" => ""},
      %{"cveID" => "not-a-cve"},
      %{"cveID" => "CVE-2026-2001\n"},
      Map.put(valid, "dateAdded", 42),
      Map.put(valid, "dueDate", []),
      Map.put(valid, "shortDescription", %{}),
      Map.put(valid, "requiredAction", false),
      Map.put(valid, "knownRansomwareCampaignUse", %{})
    ]

    for bad <- invalid, entries <- [[bad], [valid, bad], [bad, valid]] do
      assert Client.fetch(:kev, transport(kev_body(entries))) == {:error, :kev_parse_failed}
    end

    assert Client.fetch(:kev, transport(kev_body([valid, valid]))) == {:error, :kev_parse_failed}
  end

  test "NVD validates all record shapes, descriptions and the requested CVE identity" do
    cve = %{"id" => "CVE-2024-3094"}
    valid = %{"cve" => cve}

    invalid =
      [
        nil,
        [],
        %{},
        %{"cve" => nil},
        %{"cve" => %{}},
        %{"cve" => %{"id" => "CVE-2024-9999"}},
        %{"cve" => Map.put(cve, "published", %{})}
      ] ++
        for descriptions <- [
              nil,
              %{},
              [nil],
              [%{"lang" => "en"}],
              [%{"lang" => "en", "value" => []}]
            ],
            do: %{"cve" => Map.put(cve, "descriptions", descriptions)}

    for bad <- invalid, entries <- [[bad], [valid, bad], [bad, valid]] do
      assert Client.fetch({:nvd, "CVE-2024-3094"}, transport(kev_body(entries))) ==
               {:error, :nvd_parse_failed}
    end

    assert Client.fetch({:nvd, "CVE-2024-3094"}, transport(kev_body([valid, valid]))) ==
             {:error, :nvd_parse_failed}
  end

  test "valid NVD records retain optional fields and sanitized English descriptions" do
    entry = %{
      "cve" => %{
        "id" => "CVE-2024-3094",
        "published" => "2024-03-29",
        "descriptions" => [
          %{"lang" => "fr", "value" => "autre"},
          %{"lang" => "en", "value" => "Patch\u0000now"}
        ]
      }
    }

    assert {:ok, [row]} = Client.fetch({:nvd, "CVE-2024-3094"}, transport(kev_body([entry])))
    assert row.external_id == "CVE-2024-3094"
    assert row.summary == "Patch now"
    assert row.published_at == ~U[2024-03-29 00:00:00Z]

    minimal = %{"cve" => %{"id" => "CVE-2024-3094"}}

    assert {:ok, [%{summary: nil, published_at: nil}]} =
             Client.fetch({:nvd, "CVE-2024-3094"}, transport(kev_body([minimal])))
  end

  test "genuine empty feeds remain successful for both documented transport shapes" do
    body = kev_body([])

    for request <- [:kev, {:nvd, "CVE-2024-3094"}],
        transport <- [transport(body), %{req: fn _url -> {:ok, body} end}] do
      assert Client.fetch(request, transport) == {:ok, []}
    end
  end

  test "a raised or exiting transport is a controlled failure" do
    for request <- [
          fn _ -> raise "private transport detail" end,
          fn _ -> exit(:private_transport_detail) end
        ] do
      assert Client.fetch(:kev, %{req: request}) == {:error, :request_raised}
    end
  end

  test "a malformed feed is a terminal error, not a partial cache" do
    assert Client.fetch(:kev, transport("{not json")) == {:error, :kev_parse_failed}

    assert Client.fetch(:kev, transport(Jason.encode!(%{"other" => []}))) ==
             {:error, :kev_parse_failed}
  end
end
