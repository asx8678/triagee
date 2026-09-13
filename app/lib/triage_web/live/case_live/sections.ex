defmodule TriageWeb.CaseLive.Sections do
  @moduledoc """
  Section components for the review case detail view.

  Each section is a function component with the assigns it actually reads
  declared, so the case LiveView's `render/1` is a composition and a section can
  be rendered and asserted on its own. Every component renders frozen captured
  payloads only; none of them reads live inventory.
  """

  use TriageWeb, :html

  import TriageWeb.CaseLive.Format

  attr :retained_draft, :map, required: true

  def retained_draft_notice(assigns) do
    ~H"""
    <section
      :if={@retained_draft}
      id="retained-draft"
      class="notice"
      role="status"
      phx-hook="DirtyDraft"
      data-dirty="true"
    >
      <h2>Unsaved draft retained for case #{@retained_draft.case_id}</h2>
      <p>
        The route changed, not the draft's identity. Return to that case to continue, or explicitly discard it. Other assessment forms are locked until then. This draft exists only in this connected session.
      </p>
      <div class="cluster">
        <.link
          id="return-to-draft"
          data-draft-preserving="true"
          patch={~p"/cases/#{@retained_draft.case_id}"}
          class="button button-secondary"
        >Return to draft</.link>
        <button
          id="retained-discard-btn"
          type="button"
          phx-click="discard_draft"
          class="button button-secondary"
        >Discard retained draft…</button>
      </div>
    </section>
    """
  end

  attr :discard_confirm?, :boolean, required: true
  attr :retained_draft, :map, required: true

  def discard_confirm(assigns) do
    ~H"""
    <div
      :if={@discard_confirm?}
      id="discard-draft-confirm"
      class="notice"
      role="alert"
      phx-hook="FocusReturn"
      data-return-focus={if @retained_draft, do: "retained-discard-btn", else: "review_applicability"}
    >
      <p>Discard this unsaved assessment? This cannot be undone. Saved history is unchanged.</p>
      <div class="cluster">
        <button
          id="discard-confirm-btn"
          type="button"
          phx-click="discard_confirmed"
          class="button button-secondary"
        >Yes, discard draft</button>
        <button
          id="discard-cancel-btn"
          type="button"
          phx-click="discard_cancel"
          class="button button-secondary"
        >Keep draft</button>
      </div>
    </div>
    """
  end

  attr :evidence, :map, required: true
  attr :evidence_status, :atom, required: true
  attr :snapshot, :map, default: nil
  attr :latest_review, :map, default: nil
  attr :case, :map, required: true
  attr :retained_draft, :map, default: nil
  attr :notice, :atom, default: nil
  attr :refresh_confirm?, :boolean, default: false

  def evidence_snapshot(assigns) do
    ~H"""
    <section
      id="evidence-snapshot"
      class="case-summary stack"
      aria-labelledby="evidence-heading"
    >
      <div class="section-header">
        <h2 id="evidence-heading">Captured evidence</h2>
        <.status_badge label={evidence_label(@evidence_status)} />
      </div>
      <p :if={@snapshot} class="supporting">
        Snapshot v{@snapshot.version} · Captured <.timestamp value={@snapshot.captured_at} />
      </p>
      <p :if={is_nil(@snapshot)} class="notice">
        No evidence snapshot is available. Do not assess missing evidence.
      </p>
      <dl class="evidence-grid">
        <div class="key-value">
          <dt>Package · installed version</dt><dd>
            {text(@evidence.finding[:package_name])}
            <code>{text(@evidence.finding[:package_version])}</code>
          </dd>
        </div>
        <div class="key-value">
          <dt>Scanner severity</dt><dd>
            <.status_badge label={text(@evidence.finding[:severity])} kind="severity" />
          </dd>
        </div>
        <div class="key-value">
          <dt>Reported fixed version</dt><dd>{text(@evidence.finding[:fix])}</dd>
        </div>
        <div class="key-value">
          <dt>Source</dt><dd>{source_label(@evidence.source)}</dd>
        </div>
      </dl>
      <.technical_value
        id="case-image-reference"
        label="Image reference"
        value={image_reference(@evidence.image)}
      />
      <p id="case-assessment-state" class="supporting">
        <%= if @latest_review do %>
          Assessment recorded · Saved <.timestamp value={@latest_review.inserted_at} />
          · {if @latest_review.snapshot_id == @case.current_snapshot_id,
            do: "Recorded for displayed snapshot",
            else: "Needs revalidation — recorded for older snapshot"}
        <% else %>
          No assessment recorded
        <% end %>
      </p>
      <section
        id="evidence-limitations"
        class="evidence-limitations stack"
        aria-labelledby="evidence-limitations-heading"
      >
        <h3 id="evidence-limitations-heading">Evidence limitations</h3>
        <p class="supporting">
          Frozen local snapshot — not live inventory, production freshness, verified remediation or mitigation evidence.
        </p>
        <details id="evidence-limitations-details" class="disclosure">
          <summary>Read full limitations</summary>
          <p>
            Frozen local evidence, not live inventory or proof of production freshness. A reported fix is not a verified fix.
          </p>
          <p :if={@evidence.finding[:suppressed]}>
            Suppressed in captured inventory — not mitigation evidence.
          </p>
          <p :if={@evidence.finding[:resolved_at]}>
            No longer observed at capture:
            <.timestamp value={@evidence.finding[:resolved_at]} />. This is not verified remediation.
          </p>
          <p class="supporting">{text(@evidence.coverage)}</p>
        </details>
      </section>
      <.notice
        :if={@evidence_status == :changed or @notice == :evidence_stale}
        id="evidence-stale"
        kind="warning"
        title="Local evidence changed"
      >
        The local source differs from the captured snapshot, or the submitted snapshot is no longer current. New assessments are blocked until you explicitly refresh evidence and re-check your draft. Reloading the case does not capture evidence.
      </.notice>
      <.notice
        :if={@evidence_status == :source_out_of_scope or @notice == :source_out_of_scope}
        id="source-out-of-scope"
        kind="warning"
      >
        No active placement remains in the saved scope. New captures and assessments are blocked; frozen evidence and history remain readable.
      </.notice>
      <.notice :if={@evidence_status == :source_missing} id="source-missing" kind="warning">
        Source data is unavailable. New captures and assessments are blocked. Missing data is not evidence of safety.
      </.notice>
      <div class="cluster">
        <button
          id="reload-case"
          type="button"
          phx-click="reload"
          phx-disable-with="Reloading…"
          class="button button-secondary"
        >Reload saved case</button>
        <button
          id="refresh-evidence-btn"
          type="button"
          phx-click="refresh_evidence"
          disabled={not is_nil(@retained_draft)}
          class="button button-secondary"
        >Refresh evidence…</button>
      </div>
      <p class="supporting">
        Reload reads saved history only. Refresh may append a new snapshot; neither saves an assessment.
      </p>
      <div
        :if={@refresh_confirm?}
        id="refresh-evidence-confirm"
        class="notice"
        role="alert"
        phx-hook="FocusReturn"
        data-return-focus="refresh-evidence-btn"
      >
        <h3>Recapture evidence now?</h3>
        <p>
          Changed content appends a snapshot and revision; older evidence and reviews stay unchanged. Your draft and original binding are kept, never submitted automatically.
        </p>
        <div class="cluster">
          <button
            id="refresh-evidence-confirm-btn"
            type="button"
            phx-click="refresh_evidence_confirmed"
            phx-disable-with="Recapturing…"
            class="button"
          >Yes, recapture now</button>
          <button
            id="refresh-evidence-cancel-btn"
            type="button"
            phx-click="refresh_evidence_cancel"
            class="button button-secondary"
          >Cancel</button>
        </div>
      </div>
    </section>
    """
  end

  attr :case, :map, required: true
  attr :expected_revision, :integer, required: true
  attr :expected_snapshot_id, :integer, required: true
  attr :dirty?, :boolean, required: true
  attr :notice, :atom, default: nil
  attr :rebind_required?, :boolean, required: true
  attr :rebind_confirm?, :boolean, required: true
  attr :review_form, :map, required: true
  attr :idempotency_token, :string, required: true
  attr :applicability_options, :list, required: true
  attr :priority_options, :list, required: true
  attr :next_action_options, :list, required: true
  attr :evidence_status, :atom, required: true
  attr :snapshot, :map, default: nil
  attr :retained_draft, :map, default: nil

  def review_section(assigns) do
    ~H"""
    <section
      id="review-section"
      class="assessment-panel stack"
      aria-labelledby="assessment-heading"
    >
      <h2 id="assessment-heading">Local assessment</h2>
      <p id="case-banner" class="supporting">
        Saved locally by unauthenticated local-operator. This does not approve an exception, suppress a finding, or verify a fix.
      </p>
      <p id="draft-binding" class="supporting">
        Draft binding: case #{@case.id} · revision {@expected_revision} · snapshot #{@expected_snapshot_id}.
        <strong :if={@dirty?}>Unsaved changes</strong>
      </p>
      <div id="assessment-feedback" aria-live="polite">
        <.notice :if={@notice == :conflict} id="case-conflict" kind="warning">
          This case changed. Your draft remains bound to revision {@expected_revision} and snapshot #{@expected_snapshot_id}; nothing was overwritten. Reload the saved case, inspect the newer history/evidence, then choose “Use reviewed evidence for draft”.
        </.notice>
        <.notice :if={@notice == :token_reuse} id="token-reuse" kind="warning">
          This token already belongs to a different assessment. Your draft was kept. Reload, inspect the saved history, then choose “Use reviewed evidence for draft” to explicitly start a new submission token.
        </.notice>
        <.notice :if={@notice == :invalid_request} id="invalid-request" kind="error">
          Malformed or unconfirmed request; nothing was written. Your draft was kept. Reload the saved case and re-check its binding before retrying.
        </.notice>
        <.notice :if={@notice == :not_found} id="case-missing" kind="error">
          The saved case could not be loaded. Your draft was kept. Retry “Reload saved case”; do not refresh or resubmit until it is available.
        </.notice>
        <.notice :if={@notice == :validation} id="review-validation" kind="error">
          Assessment not saved. Correct the marked fields; your draft and binding were kept.
        </.notice>
        <.notice :if={@notice == :evidence_refreshed} id="evidence-refreshed">
          A new evidence snapshot was recorded. Your draft was not saved or rebound. Inspect the evidence before choosing “Use reviewed evidence for draft”.
        </.notice>
        <.notice :if={@notice == :draft_recovered} id="draft-recovered">
          Draft recovered with its original case, revision, snapshot and submission token. Check the binding before saving.
        </.notice>
        <.notice :if={@notice == :recovery_failed} id="draft-recovery-failed" kind="warning">
          Draft text recovered, but its original binding could not be verified. Saving is blocked. Check this case's evidence and explicitly rebind, or discard the draft.
        </.notice>
        <.notice :if={@notice == :draft_rebound} id="draft-rebound">
          Draft explicitly bound to the reviewed evidence with a new submission token. Nothing has been saved; re-check all fields before saving.
        </.notice>
      </div>
      <div :if={@rebind_required?} id="draft-binding-conflict" class="notice">
        <p>
          Draft binding needs review. Displayed case: revision {@case.revision}, snapshot #{@case.current_snapshot_id}. The draft still has its original binding above.
        </p>
      </div>
      <button
        :if={@dirty?}
        id="rebind-draft-btn"
        type="button"
        phx-click="rebind_draft"
        class="button button-secondary"
      >Use reviewed evidence for draft…</button>
      <div
        :if={@rebind_confirm?}
        id="rebind-draft-confirm"
        class="notice"
        role="alert"
        phx-hook="FocusReturn"
        data-return-focus="rebind-draft-btn"
      >
        <p>
          Have you checked the displayed evidence and newer history? Keep all draft fields, bind them to revision {@case.revision} / snapshot #{@case.current_snapshot_id}, and issue a new submission token? This does not save anything.
        </p>
        <div class="cluster">
          <button
            id="rebind-confirm-btn"
            type="button"
            phx-click="rebind_confirmed"
            class="button button-secondary"
          >Yes, use reviewed evidence</button>
          <button
            id="rebind-cancel-btn"
            type="button"
            phx-click="rebind_cancel"
            class="button button-secondary"
          >Keep original binding</button>
        </div>
      </div>
      <.form
        id="review-form"
        for={@review_form}
        phx-change="validate"
        phx-auto-recover="recover_draft"
        phx-submit="save"
        phx-hook="DirtyDraft"
        data-dirty={to_string(@dirty?)}
      >
        <input type="hidden" name="meta[case_id]" value={@case.id} />
        <input type="hidden" name="meta[expected_revision]" value={@expected_revision} />
        <input type="hidden" name="meta[expected_snapshot_id]" value={@expected_snapshot_id} />
        <input type="hidden" name="meta[idempotency_token]" value={@idempotency_token} />
        <fieldset disabled={not is_nil(@retained_draft)}>
          <legend class="supporting">All four fields are required</legend>
          <.input
            field={@review_form[:applicability]}
            type="select"
            label="Applicability *"
            options={@applicability_options}
            prompt="Select applicability"
            required
            aria-describedby="applicability-help"
          />
          <p id="applicability-help" class="supporting">
            “Not affected” requires evidence in your rationale. Choose “Unknown” when applicability is unclear.
          </p>
          <.input
            field={@review_form[:priority]}
            type="select"
            label="Priority *"
            options={@priority_options}
            prompt="Select priority"
            required
            aria-describedby="priority-help"
          />
          <p id="priority-help" class="supporting">
            Review urgency, not scanner severity or approval.
          </p>
          <.input
            field={@review_form[:next_action]}
            type="select"
            label="Next action *"
            options={@next_action_options}
            prompt="Select next action"
            required
            aria-describedby="next-action-help"
          />
          <p id="next-action-help" class="supporting">
            Records a proposed next step; it does not execute it.
          </p>
          <.input
            field={@review_form[:rationale]}
            type="textarea"
            label="Rationale *"
            rows="4"
            maxlength="2000"
            required
            aria-describedby="rationale-help"
          />
          <p id="rationale-help" class="supporting">
            Explain applicability, evidence and next step. Maximum 2,000 characters.
          </p>
          <div id="assessment-actions" class="cluster assessment-actions">
            <button
              id="save-review-btn"
              type="submit"
              disabled={@rebind_required? or @evidence_status != :current or is_nil(@snapshot)}
              phx-disable-with="Saving…"
              data-confirm="Save this assessment to local append-only history? This does not approve an exception or verify a fix."
              class="button"
            >Save local assessment</button>
            <button
              :if={@dirty?}
              id="discard-draft-btn"
              type="button"
              phx-click="discard_draft"
              class="button button-secondary"
            >Discard draft…</button>
          </div>
        </fieldset>
      </.form>
    </section>
    """
  end

  attr :evidence, :map, required: true
  attr :snapshot, :map, default: nil
  attr :case, :map, required: true
  # The two stream collections this section renders, as the LiveView's
  # `streams` map holds them.
  attr :streams, :map, required: true

  def case_details(assigns) do
    ~H"""
    <section
      id="case-details"
      class="case-details stack"
      aria-label="Detailed captured evidence and history"
    >
      <details id="evidence-details" class="disclosure">
        <summary>Detailed captured evidence · description, placements and lifecycle</summary>
        <.evidence_facts evidence={@evidence} id="current-evidence" />
      </details>
      <details id="technical-metadata" class="disclosure">
        <summary>Technical metadata · digest, content hash, schema and pointers</summary>
        <.technical_value
          id="case-image-digest"
          label="Image digest"
          value={@evidence.image[:digest]}
        />
        <.technical_value
          id="case-content-hash"
          label="Snapshot content hash"
          value={@snapshot && @snapshot.payload_hash}
        />
        <dl class="evidence-grid">
          <div class="key-value">
            <dt>Payload schema</dt><dd>{text(@evidence.schema_version)}</dd>
          </div>
          <div class="key-value">
            <dt>Current snapshot id</dt><dd>{text(@case.current_snapshot_id)}</dd>
          </div>
        </dl>
      </details>
      <details id="case-history" class="disclosure">
        <summary>Case history · append-only assessments and events</summary>
        <p class="supporting">
          Newest save/event time first. Assessments remain attached to the snapshot they reviewed.
        </p>
        <div id="case-timeline" phx-update="stream" class="event-list">
          <article :for={{id, entry} <- @streams.timeline} id={id} class="event-item">
            <div class="section-header">
              <h3>
                {if entry.type == :review,
                  do: "Manual assessment — #{label(entry.applicability)}",
                  else: label(entry.kind)}
              </h3>
              <span>Saved <.timestamp value={entry.at} /></span>
            </div>
            <p :if={entry.type == :review}>
              Priority: {label(entry.priority)} · Next action: {label(entry.next_action)}
            </p>
            <p :if={entry.type == :review and entry.rationale}>{entry.rationale}</p>
            <p :if={entry.type == :review} class="supporting">
              Saved against snapshot v{entry.snapshot_version} by {entry.actor}
            </p>
            <.status_badge
              :if={entry.type == :review and entry.is_stale}
              label="Needs revalidation — saved against older evidence"
              kind="warning"
            />
            <p :if={entry.type == :event} class="supporting">
              Case revision {entry.case_revision} · actor {entry.actor}<span :if={entry.snapshot_id}> · snapshot #{entry.snapshot_id}</span><span :if={
                entry.review_id
              }> · assessment #{entry.review_id}</span>
            </p>
            <details :if={entry.detail_pairs != []} class="disclosure">
              <summary>Recorded event details</summary>
              <dl class="evidence-grid">
                <div :for={pair <- entry.detail_pairs} class="key-value">
                  <dt>{pair.key}</dt><dd>{pair.value}</dd>
                </div>
              </dl>
            </details>
          </article>
        </div>
      </details>
      <details id="snapshots-section" class="disclosure">
        <summary>Evidence snapshots · older evidence stays inspectable</summary>
        <div id="snapshots" phx-update="stream" class="stack">
          <details :for={{id, snapshot} <- @streams.snapshots} id={id} class="disclosure">
            <summary>
              Snapshot v{snapshot.version}{if(snapshot.is_current,
                do: " — latest captured",
                else: " — superseded"
              )}
            </summary>
            <p>Captured <.timestamp value={snapshot.captured_at} /></p>
            <.technical_value
              id={"snapshot-hash-#{snapshot.id}"}
              label="Snapshot content hash"
              value={snapshot.payload_hash}
            />
            <.evidence_facts
              evidence={snapshot.evidence}
              id={"historical-evidence-#{snapshot.id}"}
            />
          </details>
        </div>
      </details>
    </section>
    """
  end

  # All detailed facts come from immutable captured payloads, never live preloads.
  attr :evidence, :map, required: true
  attr :id, :string, required: true

  def evidence_facts(assigns) do
    ~H"""
    <dl class="evidence-grid">
      <div class="key-value">
        <dt>Advisory</dt><dd>{text(@evidence.finding[:cve])}</dd>
      </div>
      <div class="key-value">
        <dt>Package · installed version</dt><dd>
          {text(@evidence.finding[:package_name])} {text(@evidence.finding[:package_version])}
        </dd>
      </div>
      <div class="key-value">
        <dt>Scanner severity</dt><dd>{text(@evidence.finding[:severity])}</dd>
      </div>
      <div class="key-value">
        <dt>Reported fixed version</dt><dd>{text(@evidence.finding[:fix])}</dd>
      </div>
      <div class="key-value">
        <dt>First observed</dt><dd><.timestamp value={@evidence.finding[:first_seen]} /></dd>
      </div>
      <div class="key-value">
        <dt>Last observed</dt><dd><.timestamp value={@evidence.finding[:last_seen]} /></dd>
      </div>
      <div :if={@evidence.finding[:resolved_at]} class="key-value">
        <dt>No longer observed in local inventory</dt><dd>
          <.timestamp value={@evidence.finding[:resolved_at]} /> — not verified remediation
        </dd>
      </div>
      <div :if={@evidence.finding[:suppressed]} class="key-value">
        <dt>Captured suppression</dt><dd>Suppressed — not mitigation evidence</dd>
      </div>
      <div class="key-value">
        <dt>Scanner description (captured)</dt><dd>{text(@evidence.finding[:description])}</dd>
      </div>
    </dl>
    <.technical_value
      id={"#{@id}-image"}
      label="Image reference"
      value={image_reference(@evidence.image)}
    />
    <.technical_value id={"#{@id}-digest"} label="Image digest" value={@evidence.image[:digest]} />
    <h3>Scoped placements (captured)</h3>
    <p :if={@evidence.placements == []} class="muted">No placements captured.</p>
    <div
      :if={@evidence.placements != []}
      class="table-region"
      role="region"
      tabindex="0"
      aria-label="Captured scoped placements"
    >
      <table class="data-table">
        <thead>
          <tr>
            <th scope="col">Team</th><th scope="col">Namespace</th><th scope="col">Environment</th><th scope="col">
              Placement state
            </th><th scope="col">First observed</th><th scope="col">Last observed</th>
          </tr>
        </thead>
        <tbody>
          <tr :for={placement <- @evidence.placements}>
            <td>{text(placement.owner)}</td><td>{text(placement.namespace)}</td><td>
              {text(placement.environment)}
            </td><td>{active_label(placement.active)}</td><td>
              <.timestamp value={placement.first_seen} />
            </td><td><.timestamp value={placement.last_seen} /></td>
          </tr>
        </tbody>
      </table>
    </div>
    <h3>Finding lifecycle (captured)</h3>
    <p :if={@evidence.events == []} class="muted">No lifecycle events captured.</p>
    <ul class="event-list">
      <li :for={event <- @evidence.events} class="event-item">
        {label(event.event)} ·
        <.timestamp value={event.occurred_at} /><p :if={event.note}>{text(event.note)}</p>
      </li>
    </ul>
    <p class="supporting">{text(@evidence.coverage)}</p>
    """
  end
end
