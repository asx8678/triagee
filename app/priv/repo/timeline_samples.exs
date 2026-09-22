if Mix.env() != :dev, do: raise("Timeline samples are for the local development database only")
Logger.configure(level: :warning)
Triage.Seeds.TimelineSamples.seed!()
IO.puts("Added missing fictional Timeline samples: CVE-2099-9028, CVE-2099-9029, CVE-2099-9030.")
