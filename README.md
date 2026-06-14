# whawty.aptrepo

whawty.aptrepo is a simple tool for creating and maintaining an APT package repository. It is similar to what reprepro does, but
it tries to address two issues I have with it.
The first issue is that reprepro does not allow multiple versions of the same package within a single distribution. The other problem
is that reprepro uses a single shared pool directory for all distributions. This means that it prevents you from serving different
files per distribution for a given `pkgname_version_arch`-triple. In the upstream Debian and Ubuntu repositories, such a mismatch is
disallowed for good reasons. However, for private repositories, this limitation makes less sense and complicates the way packages must
be built for specific distributions.

There is also one feature that is entirely missing from reprepro: a nice web UI. The UI does not require any running code on the server,
but is implemented purely in static HTML and JavaScript running inside the browser. All that is needed for the UI to work is a simple
JSON document describing the structure of the repository (distributions, components, and architectures). All package information is then
loaded directly from the `Packages` index files.

In case it is not already obvious, most of the design decisions have been made with the assumption that repositories managed using this
tool will not be very large. I have no plans to support large or huge repositories with this tool.

Full disclosure: the first few commits in this Git repository were entirely vibe-coded using Claude Sonnet 4.6 and Opus 4.8. However, I
have since spent several hours heavily refactoring the code, again with the help of Claude, to make it easier to review. I then performed
a manual review of all parts of the main Python script, which surfaced a few issues, though not many. Those have been fixed, and I am now
confident that the code does what it is supposed to do.
That being said, the HTML and CSS files that are part of the UI have not been scrutinized as thoroughly. The reason is that, while my Python
knowledge is decent, my experience with modern JavaScript and CSS is very limited. However, I believe that, due to the way the UI has been
implemented (using only static files on the server), it cannot directly harm the repository server. The only attack surface I can think of
is an XSS vulnerability in which a malicious package contains problematic metadata (for example, in the description field). Together with
Claude, I modified the original JavaScript to guard against this. However, I am not an experienced JavaScript developer and can therefore say
little about the quality of the resulting code.
The UI is completely optional, so if you do not trust it, simply do not deploy it. However, I think that if somebody is able to inject a
Debian package with a malicious description field into your repository, you are likely already dealing with more serious security issues.


## License

    3-clause BSD

    © 2026 whawty contributors (see AUTHORS file)
