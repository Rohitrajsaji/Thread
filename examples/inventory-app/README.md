# Inventory Reservations

This fixture supplies the INV-101 story, OpenAPI contract, and executable tests for the Thread release walkthrough.

## Run the release walkthrough

From the Thread checkout with its development dependencies installed:

```sh
python -m pytest tests/integration/test_approval_lifecycle.py
```

The walkthrough makes separate temporary Git copies of the fixture. Track 1 starts with a typo in the inventory heading and corrects it without spec or plan approval. Track 3 starts with an unimplemented reservation endpoint and uses the INV-101 story and OpenAPI contract to require spec and plan review. A mock adapter applies the reference changes through the normal worker and worktree path. Review the resulting diff, verify the exact proposal, and merge through the authenticated Approval API in both tracks.

The Track 3 restart check closes the first MCP subprocess while a spec is pending, records a comment and approval in the local review service, and resumes at plan drafting in a new MCP process.

The fixture also has standalone acceptance tests:

```sh
cd examples/inventory-app
python -m pip install '.[test]'
python -m pytest
```

- BR-INV-01 checks that racing requests for one unit yield HTTP 201 and HTTP 409 and persist one reservation.
- BR-INV-02 uses an injected clock to check that an expired hold becomes available again without cancellation.
- The OpenAPI test checks the runtime schema against the committed contract and exercises the declared cancel and missing-resource responses.
