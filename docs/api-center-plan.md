# API Center plan: manual verification

No wizard is required. This records a human observation; it never deploys runtime.

1. Open `api-center-plan-request.json` in your private operator state directory.
   Open its `portalUrl` and confirm the actual resource using your existing account.
2. Inspect the displayed current plan. If necessary, use **Overview > Manage plan**
   to view it; do not select an upgrade or submit a change.
3. Save a private capture showing the resource context and current plan, without
   credentials or unrelated account details. Keep it outside Git, owned by you,
   mode `0600`, nonempty and at most 10 MiB.
4. Record the exact displayed plan, actual observation time with UTC offset,
   and absolute capture path. Do not infer the plan or substitute the current time.
   The existing acceptance contract requires an actual **Free** observation.
5. Supply those three values to the assisting operator, or create the private
   observation JSON using the [binding fields and example](operator.md#record-the-human-observation-explicitly-resume).
   Then record it with the configured operator environment:

   ```sh
   python -m citadel.operator record-plan-observation --state-dir "$STATE_DIR" \
     --observation "$STATE_DIR/portal-observation.json" --evidence "$CAPTURE"
   ```

After successful recording, explicitly resume the same deployment. Recording
proof alone does not load data, build images, start workloads or claim acceptance.
