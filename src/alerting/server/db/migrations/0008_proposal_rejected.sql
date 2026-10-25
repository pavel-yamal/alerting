-- A proposal a decision-maker turned down.
--
-- A proposal has no deadline any more: it waits for its signatures however long that
-- takes. One nobody wants would then wait for ever, one careless signature away from
-- going out, so any decision-maker can close it: status 'rejected', and who and when
-- here as well as in the audit chain, for the screens to show.
ALTER TABLE proposals ADD COLUMN rejected_by text;
ALTER TABLE proposals ADD COLUMN rejected_at bigint;
