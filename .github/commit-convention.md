# Commit Convention

Commits in this repository use short, imperative subjects that name the source and the section. No type prefixes such as `feat:` or `fix:`.

## Subject line

- Imperative mood, capitalised, no trailing period, 72 characters or fewer.
- Start with a verb that says what happened to the list:
  - `Add` - new entries: `Add ThreatView feeds to Indicators`
  - `Archive` - moving entries to `archived.md`: `Archive OpenIOC 1.1 and NSHC IoC-List`
  - `Update` - changing a link or description: `Update Unit 42 description`
  - `Remove` - deleting entries outright, which should be rare
  - `Rename` - renaming sections or entries: `Rename Snort section`
- Name the source and, when adding, the section it went into.
- Group related changes in one commit and join them with commas or `and`, for example `Add Volexity, HvS-Consulting and Elastic sources`.

## Body

Optional. Use it when the reason isn't obvious from the subject, for example why a source was archived or why a link changed. Wrap at 72 characters.

## Tooling and repository changes

Changes to scripts, CI or docs follow the same style: `Run CI on main only now that the default branch is renamed`.
