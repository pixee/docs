# Website

This website is built using [Docusaurus 3](https://docusaurus.io/), a modern static website generator.

### Installation

```
$ yarn
```

### Local Development

```
$ yarn start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

### Formatting

Uses Prettier to maintain consistent code formatting. Configure your editor to
use Prettier on save, and/or remember to run `yarn format` to format the source.

### Dependency maintenance

Renovate handles the routine work on its own (in-range bumps, lockfile
refreshes, security PRs) - see `renovate.json`. For the periodic manual sweep
that Renovate can't do unattended, run:

```
$ scripts/upgrade-deps.sh --dry-run   # report what's available
$ scripts/upgrade-deps.sh --format    # apply, then absorb formatting churn
```

It pins every direct dependency to its newest version (including majors),
syncs the Node version across `package.json`, `.node-version` and both
workflows, then verifies
with the same steps CI runs - `yarn install --frozen-lockfile`,
`yarn check-format`, and `yarn build`. The build matters: `onBrokenLinks` is
set to `"throw"`, so an upgrade really can fail it. Nothing is committed or
pushed; review the diff yourself. `--help` lists the other options.

Invoke it directly, not via `yarn` - Yarn 1 enforces the `engines` floor on
`yarn run`, which would fail before the script can handle a Node mismatch.

### Build

```
$ yarn build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

### Deployment

Using SSH:

```
$ USE_SSH=true yarn deploy
```

Not using SSH:

```
$ GIT_USER=<Your GitHub username> yarn deploy
```

If you are using GitHub pages for hosting, this command is a convenient way to build the website and push to the `gh-pages` branch.
