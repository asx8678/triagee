defmodule Triage.Import.Parse do
  @moduledoc """
  Parsing, validation and normalization for the snapshot import: strict, pure
  and total, reporting every problem with its JSON path instead of stopping at
  the first. Nothing here reads or writes the database.

  These functions are public only so the other import stages can call them; they
  are internal to the import pipeline and are not part of the application API.
  """

  use Triage.Import.Contract

  ## Parsing and normalization

  def normalize(raw) do
    errors =
      []
      |> check_unknown_keys(raw, @image_root_keys, "$")
      |> check_format(raw)
      |> check_version(raw)

    {source, source_errors} = optional_text(raw, "source", "$")
    {generated_at, generated_errors} = optional_time(raw, "generated_at", "$")
    {images, image_errors} = normalize_images(raw)

    errors = errors ++ source_errors ++ generated_errors ++ image_errors

    if errors == [] do
      {:ok,
       %{
         format: @format,
         version: @version,
         source: source,
         generated_at: generated_at,
         images: images
       }}
    else
      {:error, errors}
    end
  end

  # Rebuild the string-keyed raw shape so the same strict parser can validate a
  # mutable normalized map at every public write boundary. Non-map values pass
  # through unchanged so the parser reports "expected an object" for them.
  def snapshot_to_raw(snapshot) do
    if is_map(snapshot) do
      %{
        "format" => Map.get(snapshot, :format),
        "version" => Map.get(snapshot, :version),
        "source" => Map.get(snapshot, :source),
        "generated_at" => time_to_raw(Map.get(snapshot, :generated_at)),
        "images" => list_to_raw(Map.get(snapshot, :images), &image_to_raw/1)
      }
    else
      snapshot
    end
  end

  def image_to_raw(%{} = image) do
    %{
      "digest" => Map.get(image, :digest),
      "repository" => Map.get(image, :repository),
      "tag" => Map.get(image, :tag),
      "description" => Map.get(image, :description),
      "placements" => list_to_raw(Map.get(image, :placements), &placement_to_raw/1),
      "findings" => list_to_raw(Map.get(image, :findings), &finding_to_raw/1)
    }
  end

  def image_to_raw(other), do: other

  def placement_to_raw(%{} = placement) do
    %{
      "namespace" => Map.get(placement, :namespace),
      "owner" => Map.get(placement, :owner),
      "environment" => Map.get(placement, :environment),
      "active" => Map.get(placement, :active),
      "first_seen" => time_to_raw(Map.get(placement, :first_seen)),
      "last_seen" => time_to_raw(Map.get(placement, :last_seen))
    }
  end

  def placement_to_raw(other), do: other

  def finding_to_raw(%{} = finding) do
    %{
      "cve" => Map.get(finding, :cve),
      "package_name" => Map.get(finding, :package_name),
      "package_version" => Map.get(finding, :package_version),
      "severity" => Map.get(finding, :severity),
      "fix" => Map.get(finding, :fix),
      "url" => Map.get(finding, :url),
      "description" => Map.get(finding, :description),
      "suppressed" => Map.get(finding, :suppressed),
      "first_seen" => time_to_raw(Map.get(finding, :first_seen)),
      "last_seen" => time_to_raw(Map.get(finding, :last_seen)),
      "resolved_at" => time_to_raw(Map.get(finding, :resolved_at)),
      "events" => list_to_raw(Map.get(finding, :events), &event_to_raw/1)
    }
  end

  def finding_to_raw(other), do: other

  def event_to_raw(%{} = event) do
    %{
      "event" => Map.get(event, :event),
      "occurred_at" => time_to_raw(Map.get(event, :occurred_at)),
      "note" => Map.get(event, :note)
    }
  end

  def event_to_raw(other), do: other

  def list_to_raw(list, fun) when is_list(list), do: Enum.map(list, fun)
  def list_to_raw(other, _fun), do: other

  def time_to_raw(%DateTime{calendar: Calendar.ISO} = datetime) do
    DateTime.to_iso8601(datetime)
  rescue
    _ -> :invalid_timestamp
  end

  def time_to_raw(%DateTime{}), do: :invalid_timestamp
  def time_to_raw(other), do: other

  def check_unknown_keys(errors, raw, allowed, path) do
    raw
    |> Map.keys()
    |> Enum.reject(&(&1 in allowed))
    |> Enum.sort()
    |> Enum.reduce(errors, fn key, acc ->
      acc ++ [problem(path, "unknown key #{inspect(key)}")]
    end)
  end

  def check_format(errors, raw) do
    case Map.get(raw, "format") do
      @format ->
        errors

      other ->
        errors ++ [problem("$.format", "expected #{inspect(@format)}, got #{inspect(other)}")]
    end
  end

  def check_version(errors, raw) do
    case Map.get(raw, "version") do
      @version -> errors
      other -> errors ++ [problem("$.version", "unsupported version #{inspect(other)}")]
    end
  end

  def normalize_images(raw) do
    case Map.get(raw, "images") do
      images when is_list(images) ->
        case budget_errors(raw) do
          [] ->
            {parsed, errors} =
              collect(images, fn index -> "$.images[#{index}]" end, &normalize_image/2)

            {parsed, errors ++ duplicate_errors(parsed)}

          budget ->
            {[], budget}
        end

      other ->
        {[], [problem("$.images", "expected a list, got #{inspect(other)}")]}
    end
  end

  # Linear, bounded collection helper: prepend then reverse, never append.
  def collect(list, path_fun, parse_fun) do
    {parsed_rev, errors_rev} =
      list
      |> Enum.with_index()
      |> Enum.reduce({[], []}, fn {item, index}, {parsed, errors} ->
        {value, errs} = parse_fun.(item, path_fun.(index))
        {[value | parsed], Enum.reverse(errs, errors)}
      end)

    {Enum.reverse(parsed_rev), Enum.reverse(errors_rev)}
  end

  def budget_errors(raw) do
    case Map.get(raw, "images") do
      images when is_list(images) ->
        errors = check_count([], "$.images", length(images), @max_images)

        {errors, placements, findings, events} =
          Enum.reduce(images, {errors, 0, 0, 0}, fn image, {errors, pc, fc, ec} ->
            {image_placements, image_findings} =
              if is_map(image) do
                {Map.get(image, "placements"), Map.get(image, "findings")}
              else
                {nil, nil}
              end

            {placement_count, errors} =
              if is_list(image_placements) do
                n = length(image_placements)
                {n, check_count(errors, "$.images[*].placements", n, @max_placements_per_image)}
              else
                {0, errors}
              end

            {finding_count, errors} =
              if is_list(image_findings) do
                n = length(image_findings)
                {n, check_count(errors, "$.images[*].findings", n, @max_findings_per_image)}
              else
                {0, errors}
              end

            {event_count, errors} =
              image_findings
              |> List.wrap()
              |> Enum.reduce({0, errors}, fn finding, {count, errors} ->
                n =
                  if is_map(finding) do
                    case Map.get(finding, "events") do
                      events when is_list(events) -> length(events)
                      _ -> 0
                    end
                  else
                    0
                  end

                {count + n,
                 check_count(errors, "$.images[*].findings[*].events", n, @max_events_per_finding)}
              end)

            {errors, pc + placement_count, fc + finding_count, ec + event_count}
          end)

        total = length(images) + placements + findings + events
        check_count(errors, "$", total, @max_total_records)

      _ ->
        []
    end
  end

  def check_count(errors, path, count, max) do
    if count > max do
      errors ++ [problem(path, "#{count} records exceed the limit of #{max}")]
    else
      errors
    end
  end

  def normalize_image(raw, path) when is_map(raw) do
    errors = check_unknown_keys([], raw, @image_keys, path)
    {digest, digest_errors} = required_text(raw, "digest", path)
    {repository, repository_errors} = optional_text(raw, "repository", path)
    {tag, tag_errors} = optional_text(raw, "tag", path)
    {description, description_errors} = optional_text(raw, "description", path)
    {placements, placement_errors} = normalize_placements(raw, path)
    {findings, finding_errors} = normalize_findings(raw, path)

    image = %{
      digest: digest,
      repository: repository,
      tag: tag,
      description: description,
      placements: placements,
      findings: findings
    }

    {image,
     errors ++
       digest_errors ++
       repository_errors ++
       tag_errors ++
       description_errors ++
       placement_errors ++
       finding_errors}
  end

  def normalize_image(_raw, path),
    do:
      {%{digest: nil, repository: nil, tag: nil, description: nil, placements: [], findings: []},
       [problem(path, "expected an object")]}

  def normalize_placements(raw, base) do
    case Map.get(raw, "placements") do
      placements when is_list(placements) ->
        {parsed, errors} =
          collect(
            placements,
            fn index -> "#{base}.placements[#{index}]" end,
            &normalize_placement/2
          )

        {parsed, errors ++ duplicate_placement_errors(parsed, base)}

      other ->
        {[], [problem("#{base}.placements", "expected a list, got #{inspect(other)}")]}
    end
  end

  def normalize_placement(raw, path) when is_map(raw) do
    errors = check_unknown_keys([], raw, @placement_keys, path)
    {namespace, e1} = required_text(raw, "namespace", path)
    {owner, e2} = required_scope(raw, "owner", path)
    {environment, e3} = required_scope(raw, "environment", path)
    {active, e4} = optional_flag(raw, "active", path)
    {first_seen, e5} = required_time(raw, "first_seen", path)
    {last_seen, e6} = required_time(raw, "last_seen", path)

    {%{
       namespace: namespace,
       owner: owner,
       environment: environment,
       active: active,
       first_seen: first_seen,
       last_seen: last_seen
     }, errors ++ e1 ++ e2 ++ e3 ++ e4 ++ e5 ++ e6}
  end

  def normalize_placement(_raw, path),
    do:
      {%{
         namespace: nil,
         owner: nil,
         environment: nil,
         active: true,
         first_seen: nil,
         last_seen: nil
       }, [problem(path, "expected an object")]}

  def normalize_findings(raw, base) do
    case Map.get(raw, "findings") do
      findings when is_list(findings) ->
        {parsed, errors} =
          collect(findings, fn index -> "#{base}.findings[#{index}]" end, &normalize_finding/2)

        {parsed, errors ++ duplicate_finding_errors(parsed, base)}

      other ->
        {[], [problem("#{base}.findings", "expected a list, got #{inspect(other)}")]}
    end
  end

  def normalize_finding(raw, path) when is_map(raw) do
    errors = check_unknown_keys([], raw, @finding_keys, path)
    {cve, e1} = required_text(raw, "cve", path)
    {package_name, e2} = required_text(raw, "package_name", path)
    {package_version, e3} = required_text(raw, "package_version", path)
    {severity, e4} = optional_severity(raw, "severity", path)
    {fix, e5} = optional_text(raw, "fix", path)
    {url, e6} = optional_text(raw, "url", path)
    {description, e7} = optional_text(raw, "description", path)
    {suppressed, e8} = optional_flag(raw, "suppressed", path)
    {first_seen, e9} = required_time(raw, "first_seen", path)
    {last_seen, e10} = required_time(raw, "last_seen", path)
    {resolved_at, e11} = optional_time(raw, "resolved_at", path)
    {events, event_errors} = normalize_events(raw, path)

    finding = %{
      cve: cve,
      package_name: package_name,
      package_version: package_version,
      severity: severity,
      fix: fix,
      url: url,
      description: description,
      suppressed: suppressed,
      first_seen: first_seen,
      last_seen: last_seen,
      resolved_at: resolved_at,
      events: events
    }

    {finding,
     errors ++ e1 ++ e2 ++ e3 ++ e4 ++ e5 ++ e6 ++ e7 ++ e8 ++ e9 ++ e10 ++ e11 ++ event_errors}
  end

  def normalize_finding(_raw, path),
    do:
      {%{
         cve: nil,
         package_name: nil,
         package_version: nil,
         severity: nil,
         fix: nil,
         url: nil,
         description: nil,
         suppressed: false,
         first_seen: nil,
         last_seen: nil,
         resolved_at: nil,
         events: []
       }, [problem(path, "expected an object")]}

  def normalize_events(raw, base) do
    case Map.get(raw, "events") do
      events when is_list(events) ->
        {parsed, errors} =
          collect(events, fn index -> "#{base}.events[#{index}]" end, &normalize_event/2)

        {parsed, errors ++ duplicate_event_errors(parsed, base)}

      other ->
        {[], [problem("#{base}.events", "expected a list, got #{inspect(other)}")]}
    end
  end

  def normalize_event(raw, path) when is_map(raw) do
    errors = check_unknown_keys([], raw, @event_keys, path)
    {event, e1} = required_event_name(raw, "event", path)
    {occurred_at, e2} = required_time(raw, "occurred_at", path)
    {note, e3} = optional_text(raw, "note", path)

    {%{event: event, occurred_at: occurred_at, note: note}, errors ++ e1 ++ e2 ++ e3}
  end

  def normalize_event(_raw, path),
    do: {%{event: nil, occurred_at: nil, note: nil}, [problem(path, "expected an object")]}

  def required_event_name(raw, key, path) do
    case Map.get(raw, key) do
      value when is_binary(value) ->
        if value in @events do
          {value, []}
        else
          {nil,
           [
             problem(
               "#{path}.#{key}",
               "expected one of #{Enum.join(@events, ", ")}, got #{inspect(value)}"
             )
           ]}
        end

      other ->
        {nil,
         [
           problem(
             "#{path}.#{key}",
             "expected one of #{Enum.join(@events, ", ")}, got #{inspect(other)}"
           )
         ]}
    end
  end

  def optional_severity(raw, key, path) do
    case Map.get(raw, key) do
      nil ->
        {nil, []}

      value when is_binary(value) ->
        if value in @severities do
          {value, []}
        else
          {nil,
           [
             problem(
               "#{path}.#{key}",
               "expected one of #{Enum.join(@severities, ", ")} or null, got #{inspect(value)}"
             )
           ]}
        end

      other ->
        {nil,
         [
           problem(
             "#{path}.#{key}",
             "expected one of #{Enum.join(@severities, ", ")} or null, got #{inspect(other)}"
           )
         ]}
    end
  end

  def required_text(raw, key, path) do
    case Map.get(raw, key) do
      value when is_binary(value) ->
        validate_text(value, key, path, true)

      other ->
        {nil, [problem("#{path}.#{key}", "expected a non-empty string, got #{inspect(other)}")]}
    end
  end

  def optional_text(raw, key, path) do
    case Map.get(raw, key) do
      nil ->
        {nil, []}

      value when is_binary(value) ->
        validate_text(value, key, path, false)

      other ->
        {nil, [problem("#{path}.#{key}", "expected a string or null, got #{inspect(other)}")]}
    end
  end

  def validate_text(value, key, path, required?) do
    cond do
      not String.valid?(value) ->
        {nil, [problem("#{path}.#{key}", "must be valid UTF-8")]}

      byte_size(value) > @max_text_bytes ->
        {nil, [problem("#{path}.#{key}", "must be at most #{@max_text_bytes} bytes")]}

      Regex.match?(@unsafe_text, value) ->
        {nil, [problem("#{path}.#{key}", "must not contain raw control characters")]}

      String.length(value) > @max_text ->
        {nil, [problem("#{path}.#{key}", "must be at most #{@max_text} characters")]}

      String.trim(value) == "" ->
        if required? do
          {nil, [problem("#{path}.#{key}", "must not be blank")]}
        else
          {nil, []}
        end

      true ->
        {if(required?, do: String.trim(value), else: value), []}
    end
  end

  # Imported owner/environment must satisfy the same contract as the UI scope
  # filter so an option offered by the feed can never be rejected by it.
  def required_scope(raw, key, path) do
    case Map.get(raw, key) do
      value when is_binary(value) ->
        validate_scope(value, key, path)

      other ->
        {nil, [problem("#{path}.#{key}", "expected a non-empty string, got #{inspect(other)}")]}
    end
  end

  def validate_scope(value, key, path) do
    cond do
      not String.valid?(value) ->
        {nil, [problem("#{path}.#{key}", "must be valid UTF-8")]}

      String.trim(value) == "" ->
        {nil, [problem("#{path}.#{key}", "must not be blank")]}

      Regex.match?(@unsafe_text, value) ->
        {nil, [problem("#{path}.#{key}", "must not contain raw control characters")]}

      byte_size(value) > @max_scope_bytes ->
        {nil, [problem("#{path}.#{key}", "must be at most #{@max_scope_bytes} bytes")]}

      String.length(value) > @scope_max ->
        {nil,
         [
           problem(
             "#{path}.#{key}",
             "must be at most #{@scope_max} characters to match the scope filter contract"
           )
         ]}

      true ->
        {String.trim(value), []}
    end
  end

  # A flag that may be absent. `nil` means "the snapshot does not state it";
  # writes then preserve the recorded local value (creation falls back to the
  # schema default) instead of silently clearing source state.
  def optional_flag(raw, key, path) do
    case Map.get(raw, key) do
      nil -> {nil, []}
      value when is_boolean(value) -> {value, []}
      other -> {nil, [problem("#{path}.#{key}", "expected a boolean, got #{inspect(other)}")]}
    end
  end

  def required_time(raw, key, path) do
    case Map.get(raw, key) do
      nil -> {nil, [problem("#{path}.#{key}", "is required")]}
      value -> parse_time(value, "#{path}.#{key}")
    end
  end

  def optional_time(raw, key, path) do
    case Map.get(raw, key) do
      nil -> {nil, []}
      value -> parse_time(value, "#{path}.#{key}")
    end
  end

  def parse_time(value, path) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {DateTime.truncate(datetime, :second), []}
      {:error, reason} -> {nil, [problem(path, "invalid ISO 8601 timestamp (#{reason})")]}
    end
  end

  def parse_time(other, path),
    do: {nil, [problem(path, "expected an ISO 8601 string, got #{inspect(other)}")]}

  def duplicate_errors(images) do
    duplicate_errors(images, "$.images[", "].digest", & &1.digest, "image digest")
  end

  def duplicate_placement_errors(placements, base) do
    duplicate_errors(
      placements,
      "#{base}.placements[",
      "]",
      &{&1.namespace, &1.owner, &1.environment},
      "placement"
    )
  end

  def duplicate_finding_errors(findings, base) do
    duplicate_errors(
      findings,
      "#{base}.findings[",
      "]",
      &{&1.cve, &1.package_name, &1.package_version},
      "finding"
    )
  end

  def duplicate_event_errors(events, base) do
    duplicate_errors(
      events,
      "#{base}.events[",
      "]",
      &{&1.event, &1.occurred_at},
      "event"
    )
  end

  def duplicate_errors(items, prefix, suffix, key_fun, label) do
    items
    |> Enum.with_index()
    |> Enum.reduce({[], MapSet.new()}, fn {item, index}, {errors, seen} ->
      key = key_fun.(item)

      if MapSet.member?(seen, key) do
        {[problem("#{prefix}#{index}#{suffix}", "duplicate #{label} #{inspect(key)}") | errors],
         seen}
      else
        {errors, MapSet.put(seen, key)}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  def problem(path, message), do: %{path: path, message: message}

  def format_errors(errors) do
    Enum.map_join(errors, "\n", fn %{path: path, message: message} -> "  #{path}: #{message}" end)
  end
end
