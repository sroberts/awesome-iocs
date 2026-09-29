# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project summary

Awesome IOCs is a curated [Awesome list](https://awesome.re) of sources of indicators of compromise and detection signatures, plus a few IOC-specific tools and formats. There is no application code: the product is `README.md`, with retired sources in `archived.md`. It is a curation, not a collection, so only add sources that can be recommended.

## Layout

- `README.md` - the list itself, grouped into sections under `## IOCs` and `## Tools`, plus `Related Lists`.
- `archived.md` - sources that are archived, superseded or unmaintained, with the reason in each description.
- `CONTRIBUTING.md` - the rules for entries. Read it before editing either list.
- `script/cibuild` - what CI runs: `mdl` over `*.md` using `.mdlrc`, then `script/check-sort`.
- `script/check-sort` - fails if entries under any heading are out of byte order.
- `script/check-sources` - flags archived, moved or stale GitHub sources; run weekly by `.github/workflows/link-check.yml` along with a lychee link check.
- `media/` - the header banner.

## Conventions

- Entry format: `- [owner/name](url) - Description ending in a period.` For sources not on GitHub, the link text is the source's name.
- One sentence per description: what the source is and why it's useful.
- Keep each section in byte (case-sensitive) order: digits, then uppercase, then lowercase. Insert entries in place; never append to the bottom.
- Link to the current canonical location. If a repository was renamed or transferred, use the new owner and name.
- Vendor-operated sources are allowed, but the description must say who operates them.
- Moving a source to `archived.md` means removing it from `README.md` and noting why, for example `Archived.` or `Last updated 2017.`
- If you add or rename a section, update the `Contents` list in `README.md`.

## Anti-patterns (do NOT)

- Don't use promotional wording such as "best", "validated" or "high-confidence" unless the source documents how it earns it.
- Don't add sources you haven't checked are live and maintained.
- Don't rely on GitHub redirects for moved repositories.
- Don't re-wrap or reformat unrelated entries; keep diffs to the lines you mean to change.
- Don't add dependencies, build tooling or generated files beyond what `script/cibuild` needs.

## Workflow

- Validate every change before calling it done:

  ```sh
  bundle install
  ./script/cibuild
  ```

- Commit messages follow `.github/commit-convention.md`.
- Pull requests use `.github/pull_request_template.md`; fill in every checklist item.
