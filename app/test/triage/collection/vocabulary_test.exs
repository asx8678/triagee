defmodule Triage.Collection.VocabularyTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Triage.Collect
  alias Triage.Collection
  alias Triage.Collection.Errors.DisabledError
  alias Triage.Collection.{FixtureContract, Live, Query, Vocabulary}

  test "A32 positive control admits only the fixture contract query documents" do
    documents = [
      Query.status_query(),
      Query.owners_query(),
      Query.image_list_query(FixtureContract.owner()),
      Query.image_detail_query(FixtureContract.image_id(), FixtureContract.engine())
    ]

    assert documents == Vocabulary.approved_documents()
    assert Enum.all?(documents, &(Vocabulary.classify(&1) == {:ok, :read}))
    assert Vocabulary.query_version() == FixtureContract.query_version()
  end

  test "A32 mutation and non-fixture documents are denied before any transport exists" do
    assert {:error, :mutation_denied} = Vocabulary.classify("mutation { deleteOwner(id: 1) }")

    assert {:error, :mutation_denied} =
             Vocabulary.classify(Query.status_query() <> " mutation { x }")

    assert {:error, :vocabulary_denied} = Vocabulary.classify("{ x }")

    assert {:error, :vocabulary_denied} =
             Vocabulary.classify(Query.image_list_query("other-owner"))

    assert {:error, :vocabulary_denied} =
             Vocabulary.classify(
               Query.image_detail_query("22222222-2222-4222-8222-222222222222", "Grype")
             )

    assert {:error, :vocabulary_denied} = Vocabulary.classify(Query.status_query() <> " ")
    assert {:error, :vocabulary_denied} = Vocabulary.classify("http://127.0.0.1/graphql")
    assert {:error, :invalid_query} = Vocabulary.classify(nil)
    refute Enum.any?(Vocabulary.__info__(:functions), fn {name, _arity} -> name == :post end)
  end

  test "the separate live entry and collect task perform no network or ingest" do
    assert Live.__info__(:functions) == [run: 0]
    assert Live.run() == {:error, :collection_disabled}
    assert Collect.execute([]) == {:error, :collection_disabled}

    assert Collect.execute(["--endpoint", "https://evil.example"]) ==
             {:error, :collection_disabled}

    assert catch_exit(Collect.run(["--fixture", "authorized_positive.json"])) == {:shutdown, 1}
    assert {:error, %DisabledError{}} = Collection.run([])
  end
end
