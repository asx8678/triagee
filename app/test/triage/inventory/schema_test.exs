defmodule Triage.Inventory.SchemaTest do
  use ExUnit.Case, async: true

  alias Triage.Inventory.{CveDetail, Finding, FindingEvent, Image, ImagePlacement}

  test "schema identities, ordered fields and timestamp types survive extraction" do
    schemas = [
      {Image, "images", ~w(id digest repository tag description inserted_at updated_at)a},
      {ImagePlacement, "image_placements",
       ~w(id image_id namespace owner environment active first_seen last_seen inserted_at updated_at)a},
      {Finding, "findings",
       ~w(id image_id cve package_name package_version severity fix url description suppressed first_seen last_seen resolved_at reopen_count inserted_at updated_at)a},
      {FindingEvent, "finding_events",
       ~w(id finding_id event occurred_at note inserted_at updated_at)a}
    ]

    for {schema, table, fields} <- schemas do
      assert schema.__schema__(:source) == table
      assert schema.__schema__(:fields) == fields
      assert schema.__schema__(:primary_key) == [:id]
      assert schema.__schema__(:type, :inserted_at) == :utc_datetime
      assert schema.__schema__(:type, :updated_at) == :utc_datetime
    end
  end

  test "image associations still resolve to the existing fully-qualified schema" do
    for schema <- [Finding, ImagePlacement] do
      assert schema.__schema__(:associations) == [:image]
      association = schema.__schema__(:association, :image)
      assert association.related == Image
      assert association.owner == schema
      assert association.owner_key == :image_id
      assert association.related_key == :id
    end

    assert Image.__schema__(:associations) == []
    # Lifecycle events intentionally have no association back to Finding.
    assert FindingEvent.__schema__(:associations) == []
    assert FindingEvent.__schema__(:type, :finding_id) == :integer
  end

  test "defaults and changeset contracts remain intact without a database" do
    assert %Finding{}.suppressed == false
    assert %Finding{}.reopen_count == 0
    assert %ImagePlacement{}.active == true
    assert %CveDetail{} == %CveDetail{cve: nil, occurrences: [], placements: []}

    for schema <- [Image, ImagePlacement, Finding, FindingEvent] do
      refute schema.changeset(struct(schema), %{}).valid?
    end

    assert Image.changeset(%Image{}, %{digest: "sha256:example"}).valid?
    now = ~U[2026-09-16 00:00:00Z]
    attrs = %{finding_id: 1, occurred_at: now}

    for event <- ~w(appeared resolved reopened) do
      assert FindingEvent.changeset(%FindingEvent{}, Map.put(attrs, :event, event)).valid?
    end

    refute FindingEvent.changeset(%FindingEvent{}, Map.put(attrs, :event, "deleted")).valid?
    finding = Finding.changeset(%Finding{}, %{})
    assert Enum.any?(finding.constraints, &(&1.type == :foreign_key and &1.field == :image_id))
    assert Enum.any?(finding.constraints, &(&1.type == :unique))
    placement = ImagePlacement.changeset(%ImagePlacement{}, %{})
    assert Enum.any?(placement.constraints, &(&1.type == :unique))
  end
end
