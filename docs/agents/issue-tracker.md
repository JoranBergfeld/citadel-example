# Issue tracker: GitHub

Issues and specs live in GitHub Issues for `JoranBergfeld/citadel-example`. Use the `gh` CLI; it infers the repo from the git remote.

## Conventions

- Create: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- Read: `gh issue view <number> --json number,title,body,labels,comments`.
- List: `gh issue list --state open --json number,title,body,labels,comments`, with appropriate label and state filters.
- Comment: `gh issue comment <number> --body "..."`.
- Apply/remove labels: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`.
- Close: `gh issue close <number> --comment "..."`.
- Sub-issues: `gh issue create --parent <parent> ...` or `gh issue edit <parent> --add-sub-issue <child>` (`gh` 2.94+). Older CLI: `gh api --method POST repos/{owner}/{repo}/issues/<parent>/sub_issues -F sub_issue_id=<child-db-id>`. If unavailable, add `Part of #<parent>` to the child and a task-list entry to the parent.

## Pull requests as a triage surface

**PRs as a request surface: no.** Set to `yes` to include external PRs in triage.

When enabled, use `gh pr view <number> --comments` and `gh pr diff <number>` to read; use `gh pr comment`, `gh pr edit`, and `gh pr close` to act. List external PRs with `gh api --paginate 'repos/{owner}/{repo}/pulls?state=open' --jq '.[] | select(.author_association | IN("OWNER","MEMBER","COLLABORATOR") | not) | {number, title, author: .user.login, author_association, labels: [.labels[].name]}'`.

Issues and PRs share a number space: resolve ambiguous references with `gh pr view <number>`, falling back to `gh issue view <number>`.

## Skill operations

- "Publish to the issue tracker": create a GitHub issue.
- "Fetch the relevant ticket": read the issue.

## Wayfinding operations

- Map: one issue labelled `wayfinder:map`, with Notes / Decisions-so-far / Fog sections.
- Children: sub-issues of the map, labelled `wayfinder:<type>` (`research`, `prototype`, `grilling`, or `task`). Use the sub-issue fallback above when unavailable.
- Blocking: native issue dependencies. Add with `gh api --method POST repos/{owner}/{repo}/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`. Fetch database IDs with `gh api repos/{owner}/{repo}/issues/<number> --jq .id`; use the database ID, not the issue number or node ID. If unavailable, use a `Blocked by: #<number>, ...` line in the child body.
- Frontier: map's open children, excluding assigned tickets and those with open blockers (`issue_dependencies_summary.blocked_by > 0`, or open issues referenced by the fallback line). First in map order wins.
- Claim: `gh issue edit <number> --add-assignee @me`, the session's first write.
- Resolve: comment with the answer, close the child, then append a gist and link to the map's Decisions-so-far.
