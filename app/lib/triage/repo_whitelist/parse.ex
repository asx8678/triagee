defmodule Triage.RepoWhitelist.Parse do
  @moduledoc """
  Reads a whitelist file whose layout is not fixed in advance: a JSON document,
  a YAML list, CSV, a Markdown table, or plain lines such as a `.trivyignore`.

  Three things are taken per entry and everything else is ignored, so the file
  can keep whatever other fields its own tooling needs:

    * the CVE id;
    * the day the entry stops applying, when the file states one;
    * a reason, when one is written next to it.

  An end date is recognised as `YYYY-MM-DD` or `DD.MM.YYYY`. It is preferred
  when it follows a word such as `expires`, `until`, `valid` or `due` (also
  `exp:` as in a `.trivyignore`); otherwise the latest date written with the
  entry is used, never one labelled as a start (`created`, `added`, `from`).
  A date is looked for on the CVE's own line, then in what is nested under it,
  then in the list item that contains it. A CSV file or Markdown table with a
  header row is read by its columns instead. Commented-out lines are not
  entries.

  The same CVE listed several times becomes one entry with the earliest end
  date, so the most urgent one is what is shown.
  """

  alias Triage.Intel.Sanitize

  @cve ~r/CVE-\d{4}-\d{4,}/i
  @iso_date ~r/(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?!\d)/
  @dotted_date ~r/(?<![\d.])(\d{1,2})\.(\d{1,2})\.(\d{4})(?![\d.])/
  @expiry_word ~r/exp|until|valid|due|end|review/i
  @start_word ~r/from|start|creat|added|since|issued/i
  @reason_key ~r/^\W*(reason|statement|justification|comment|note|description|why)\W*:\s*(.+)$/i
  @reason_name ~r/reason|statement|justif|comment|note|descr|why/i
  @max_entries 5_000
  @max_reason 300

  @typedoc "One whitelisted CVE as the file states it."
  @type entry :: %{
          cve: String.t(),
          until: Date.t() | nil,
          reason: String.t() | nil,
          occurrences: pos_integer()
        }

  @doc "Extracts the entries and names the layout that was recognised."
  @spec entries(binary()) :: %{format: :json | :table | :list | :lines, entries: [entry()]}
  def entries(content) when is_binary(content) do
    content = content |> String.replace_invalid(" ") |> String.trim_leading(<<0xFEFF::utf8>>)

    {format, found} =
      case Jason.decode(content) do
        {:ok, value} when is_map(value) or is_list(value) -> {:json, from_json(value)}
        _not_json -> from_text(content)
      end

    %{format: format, entries: found |> Enum.take(@max_entries) |> merge()}
  end

  ## JSON

  defp from_json(list) when is_list(list), do: Enum.flat_map(list, &from_json/1)

  defp from_json(%{} = map) do
    case json_entries(map) do
      [] -> map |> Map.values() |> Enum.flat_map(&from_json/1)
      entries -> entries
    end
  end

  defp from_json(value) when is_binary(value) do
    case whole_cve(value) do
      nil -> []
      cve -> [entry(cve, nil, nil)]
    end
  end

  defp from_json(_other), do: []

  # An object is an entry when a CVE id is one of its values, one of its keys,
  # or a list of ids that share the object's date and reason.
  defp json_entries(map) do
    keyed = for {key, value} <- map, cve = whole_cve(key), do: keyed_entry(cve, value)
    shared = for cve <- shared_ids(map), do: entry(cve, json_until(map), json_reason(map))

    case {keyed, own_id(map), shared} do
      {[_ | _], _own, _shared} -> keyed
      {[], cve, _shared} when is_binary(cve) -> [entry(cve, json_until(map), json_reason(map))]
      {[], nil, shared} -> shared
    end
  end

  defp keyed_entry(cve, %{} = fields), do: entry(cve, json_until(fields), json_reason(fields))
  defp keyed_entry(cve, value) when is_binary(value), do: entry(cve, latest_date(value), nil)
  defp keyed_entry(cve, _value), do: entry(cve, nil, nil)

  defp own_id(map) do
    map
    |> Enum.sort_by(fn {key, _value} -> if key =~ ~r/^(id|cve|vuln)/i, do: 0, else: 1 end)
    |> Enum.find_value(fn {_key, value} -> whole_cve(value) end)
  end

  defp shared_ids(map) do
    Enum.flat_map(map, fn {_key, value} ->
      ids = if is_list(value), do: Enum.map(value, &whole_cve/1), else: []
      if ids != [] and Enum.all?(ids), do: ids, else: []
    end)
  end

  defp json_until(map) do
    Enum.find_value(map, fn {key, value} ->
      if expiry_word?(key) and is_binary(value), do: latest_date(value)
    end)
  end

  defp json_reason(map) do
    Enum.find_value(map, fn {key, value} ->
      if key =~ @reason_name and is_binary(value), do: value
    end)
  end

  defp whole_cve(value) when is_binary(value) do
    trimmed = String.trim(value)
    if Regex.match?(~r/\A#{@cve.source}\z/i, trimmed), do: String.upcase(trimmed)
  end

  defp whole_cve(_other), do: nil

  ## Text: YAML lists, CSV, Markdown tables and plain lines

  defp from_text(content) do
    lines =
      content
      |> String.split(~r/\r\n|\n|\r/)
      |> Enum.with_index()
      |> Enum.map(fn {text, index} -> line(text, index) end)

    case table(lines) do
      nil -> free_text(lines)
      table -> {:table, table_entries(lines, table)}
    end
  end

  defp free_text(lines) do
    found =
      for current <- lines,
          not current.comment?,
          {cve, own_text} <- segments(current.text),
          own = %{current | text: own_text},
          do: entry(cve, text_until(lines, own), text_reason(lines, own))

    listed? =
      Enum.any?(lines, fn current ->
        cves(current.text) != [] and (current.item? or enclosing_items(lines, current) != [])
      end)

    {if(listed?, do: :list, else: :lines), found}
  end

  # A line usually names one CVE and is read whole. When it names several and
  # carries more than one date, each CVE gets the text that follows it, so a
  # date is not shared between neighbours.
  defp segments(text) do
    case {cves(text), date_count(text)} do
      {ids, count} when length(ids) < 2 or count < 2 ->
        Enum.map(ids, &{&1, text})

      {_several, _dates} ->
        starts =
          @cve |> Regex.scan(text, return: :index) |> Enum.map(fn [{start, _}] -> start end)

        ends = Enum.drop(starts, 1) ++ [byte_size(text)]

        starts
        |> Enum.zip(ends)
        |> Enum.map(fn {start, stop} -> binary_part(text, start, stop - start) end)
        |> Enum.map(fn part -> {part |> cves() |> hd(), part} end)
        |> Enum.uniq_by(&elem(&1, 0))
    end
  end

  defp date_count(text) do
    text = String.replace(text, @cve, " ")
    length(Regex.scan(@iso_date, text)) + length(Regex.scan(@dotted_date, text))
  end

  # A header row names the columns: one for the id, optionally one for the end
  # date and one for the reason. Rows are then read by column, so a "created"
  # column is never mistaken for an end date.
  defp table(lines) do
    with %{text: text} <- Enum.find(lines, &(not &1.blank? and not &1.comment?)),
         [] <- cves(text),
         delimiter when is_binary(delimiter) <- delimiter(text),
         header = cells(text, delimiter),
         true <- Enum.any?(header, &(&1 =~ ~r/^\W*(cve|id|vulnerab)/i)) do
      %{
        delimiter: delimiter,
        until: Enum.find_index(header, &expiry_word?/1),
        reason: Enum.find_index(header, &(&1 =~ @reason_name))
      }
    else
      _no_header -> nil
    end
  end

  defp delimiter(text) do
    [",", ";", "\t", "|"]
    |> Enum.map(&{&1, length(String.split(text, &1))})
    |> Enum.filter(fn {_delimiter, count} -> count >= 2 end)
    |> Enum.max_by(&elem(&1, 1), fn -> {nil, 0} end)
    |> elem(0)
  end

  defp cells(text, "|"),
    do: text |> String.trim() |> String.trim("|") |> String.split("|") |> Enum.map(&String.trim/1)

  defp cells(text, delimiter),
    do: text |> String.split(delimiter) |> Enum.map(&String.trim(&1, " \"'"))

  defp table_entries(lines, table) do
    for current <- lines,
        not current.comment?,
        cve <- cves(current.text),
        row = cells(current.text, table.delimiter),
        do: entry(cve, cell_date(row, table.until), cell(row, table.reason))
  end

  defp cell(_row, nil), do: nil
  defp cell(row, index), do: Enum.at(row, index)

  defp cell_date(row, index) do
    case cell(row, index) do
      nil -> nil
      text -> dates(text, :any)
    end
  end

  defp line(text, index) do
    trimmed = String.trim_leading(text)

    %{
      index: index,
      text: text,
      indent: String.length(text) - String.length(trimmed),
      blank?: trimmed == "",
      comment?: String.starts_with?(trimmed, ["#", "//", "<!--"]),
      item?: Regex.match?(~r/^-\s+\S/, trimmed)
    }
  end

  defp cves(text),
    do: @cve |> Regex.scan(text) |> Enum.map(fn [id] -> String.upcase(id) end) |> Enum.uniq()

  # The CVE's own line first, then what is nested under it, then the list
  # items around it from the inside out. An enclosing item only counts when it
  # names its date as an end date, so a date that belongs to a sibling entry
  # is never borrowed.
  defp text_until(lines, current) do
    dates(current.text, :any) ||
      block_date(nested(lines, current), :any) ||
      lines
      |> enclosing_items(current)
      |> Enum.find_value(&block_date(nested(lines, &1), :named))
  end

  defp block_date(block, mode) do
    block
    |> Enum.reject(& &1.comment?)
    |> Enum.find_value(&dates(&1.text, :named)) ||
      if(mode == :any, do: block |> Enum.reject(& &1.comment?) |> latest_in())
  end

  defp latest_in(block) do
    case block |> Enum.map(&dates(&1.text, :any)) |> Enum.reject(&is_nil/1) do
      [] -> nil
      found -> Enum.max(found, Date)
    end
  end

  # A line and everything indented deeper below it.
  defp nested(lines, start) do
    following =
      lines
      |> Enum.drop(start.index + 1)
      |> Enum.take_while(&(&1.blank? or &1.indent > start.indent))

    [start | Enum.reject(following, & &1.blank?)]
  end

  # The list items the line sits in, innermost first, with their nesting depth.
  defp enclosing_items(lines, current) do
    lines
    |> Enum.take(current.index)
    |> Enum.reverse()
    |> Enum.reduce({[], current.indent}, fn candidate, {found, indent} ->
      cond do
        candidate.blank? or candidate.indent >= indent -> {found, indent}
        candidate.item? -> {[candidate | found], candidate.indent}
        true -> {found, candidate.indent}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  defp text_reason(lines, current) do
    block =
      case enclosing_items(lines, current) do
        [item | _outer] -> nested(lines, item)
        [] -> nested(lines, current)
      end

    Enum.find_value(block, &named_reason(&1.text)) || inline_reason(current.text)
  end

  defp named_reason(text) do
    case Regex.run(@reason_key, text) do
      [_all, _key, value] -> value |> String.trim() |> String.trim("\"") |> String.trim("'")
      _none -> nil
    end
  end

  # A trailing comment, or the wordiest other cell when the row is delimited
  # and the CVE fills a cell of its own.
  defp inline_reason(text) do
    case String.split(text, ~r/\s#\s?|\s\/\/\s?/, parts: 2) do
      [_entry, comment] -> comment
      [_only] -> if delimited_row?(text), do: text |> without_ids_and_dates() |> wordiest_cell()
    end
  end

  defp delimited_row?(text) do
    row = text |> String.split(~r/[,;|\t]/) |> Enum.map(&String.trim(&1, " \"'`*"))
    length(row) >= 3 and Enum.any?(row, &whole_cve/1)
  end

  defp without_ids_and_dates(text) do
    text
    |> String.replace(@cve, " ")
    |> String.replace(@iso_date, " ")
    |> String.replace(@dotted_date, " ")
    |> String.replace(~r/\bexp:\s*/i, " ")
  end

  defp wordiest_cell(text) do
    text
    |> String.split(~r/[,;|\t]/)
    |> Enum.map(&String.trim(&1, " -*\"'`"))
    |> Enum.filter(&(&1 =~ ~r/\p{L}{3,}.*\s.*\p{L}/u))
    |> Enum.max_by(&String.length/1, fn -> nil end)
  end

  ## Dates

  defp latest_date(text), do: dates(text, :any)

  # `:named` accepts only a date that follows an end-date word; `:any` falls
  # back to the latest date on the line that is not labelled as a start.
  defp dates(text, mode) do
    text = String.replace(text, @cve, &String.duplicate(" ", String.length(&1)))
    found = iso_dates(text) ++ dotted_dates(text)
    named = for {date, context} <- found, expiry_word?(context), do: date
    other = for {date, context} <- found, not (context =~ @start_word), do: date

    case {named, mode, other} do
      {[date | _rest], _mode, _other} -> date
      {[], :any, [_ | _]} -> Enum.max(other, Date)
      _none -> nil
    end
  end

  defp iso_dates(text) do
    for [{start, _length} | _groups] = match <- Regex.scan(@iso_date, text, return: :index),
        [year, month, day] = groups(text, match),
        {:ok, date} <- [Date.new(year, month, day)],
        do: {date, context(text, start)}
  end

  defp dotted_dates(text) do
    for [{start, _length} | _groups] = match <- Regex.scan(@dotted_date, text, return: :index),
        [day, month, year] = groups(text, match),
        year in 2000..2100,
        {:ok, date} <- [Date.new(year, month, day)],
        do: {date, context(text, start)}
  end

  defp groups(text, [_whole | groups]),
    do:
      Enum.map(groups, fn {start, length} ->
        text |> binary_part(start, length) |> String.to_integer()
      end)

  # The words between the previous date, or the line start, and this date.
  defp context(text, start) do
    before = binary_part(text, 0, start)

    case Regex.split(~r/\d{4}-\d{2}-\d{2}|\d{1,2}\.\d{1,2}\.\d{4}/, before) do
      [] -> before
      parts -> List.last(parts)
    end
  end

  defp expiry_word?(text) when is_binary(text),
    do: text =~ @expiry_word and not (text =~ @start_word)

  defp expiry_word?(_other), do: false

  ## Entries

  defp entry(cve, until, reason),
    do: %{cve: cve, until: until, reason: Sanitize.text(reason, @max_reason), occurrences: 1}

  defp merge(entries) do
    entries
    |> Enum.group_by(& &1.cve)
    |> Enum.map(fn {cve, same} ->
      %{
        cve: cve,
        until:
          same |> Enum.map(& &1.until) |> Enum.reject(&is_nil/1) |> Enum.min(Date, fn -> nil end),
        reason: Enum.find_value(same, & &1.reason),
        occurrences: length(same)
      }
    end)
    |> Enum.sort_by(& &1.cve)
  end
end
