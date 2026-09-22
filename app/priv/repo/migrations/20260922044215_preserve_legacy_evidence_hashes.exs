defmodule Triage.Repo.Migrations.PreserveLegacyEvidenceHashes do
  use Ecto.Migration

  def up do
    # Evidence hashes moved from VM-state-dependent term encoding to
    # Triage.Canonical. A stored hash cannot be recomputed in the new format
    # from its recorded metadata (fields such as reopen_count were not part of
    # the recorded evidence), so preserving the binding means keeping the
    # original value auditable under evidence_hash_legacy and dropping
    # evidence_hash, which gives the row the same documented semantics as
    # earlier legacy records: covered without re-verification against current
    # evidence. Hashing *current* evidence here instead would forge a review
    # that never happened. Decisions written after this migration bind under
    # the canonical hash and re-verify as before.
    execute """
    UPDATE advisory_decisions
    SET metadata =
      jsonb_set(metadata, '{evidence_hash_legacy}', to_jsonb(metadata->>'evidence_hash'), true)
        - 'evidence_hash'
    WHERE metadata ? 'evidence_hash'
      AND metadata->>'evidence_hash' IS NOT NULL
    """
  end

  def down do
    # Restores only rows this migration converted. Decisions written after the
    # upgrade keep their canonical evidence_hash untouched.
    execute """
    UPDATE advisory_decisions
    SET metadata =
      jsonb_set(metadata, '{evidence_hash}', to_jsonb(metadata->>'evidence_hash_legacy'), true)
        - 'evidence_hash_legacy'
    WHERE metadata ? 'evidence_hash_legacy'
    """
  end
end
