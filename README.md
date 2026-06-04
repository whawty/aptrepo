# whawty.aptrepo

whawty.aptrepo is a simple tool to create and maintain an APT package repository. It is similar to what reprepro does but
tries to fix 2 issues I have with that.
The first issue is that reprepro does not allow multiple versions of the same package within one dist. The other problem is
that reprepro only has a single shared pool directory for all dists. This means that it prevents you from serving different
files per dist for a given pkgname_version_arch-triple. In the upstream repos of Debian or Ubuntu such a mismatch is disallowed
for good reasons, but for private repos this limitation makes less sense and complicates the way you have to build packages for
specific dists.

There is also one feature that is missing in reprepro entirely: a nice Web UI. The UI does not need any running code on the
server but is implemented purely in static HTML and JavaScript running inside the browser. All that is needed for the UI to work
is a simple JSON document describing the structure of the repo (dists, components and architectures). All the package
information is then loaded from the Packages index files directly.

In case it isn't already obvious, most of the design decisions have been made with the assumption that the repository that is
managed using this tool is not very big. I have no plans to support bigger or even huge repositories using this tool.

Full disclosure: the first few commits in this Git repo are completely vibe coded using Claude Sonnet 4.6 and Opus 4.8. Before
this gets deployed in production I will however manually check all the code for problems. Once I am done with this I will
update this note here. Until then: PLEASE don't trust this!!!

## License

    3-clause BSD

    © 2026 whawty contributors (see AUTHORS file)
