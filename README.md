# arch-signoff

Run `signoff` to get a list of packages you can sign off. `signoff -i` lets you
interactively sign off packages.

To simplify authentication, specify your ArchWeb username and password in the
`ARCHWEB_USERNAME` and `ARCHWEB_PASSWORD` environment variables. For instance,
using [pass][1]:

    alias signoff='ARCHWEB_PASSWORD="$(pass archweb)" signoff'

See LICENSE for license details.

[1]: https://www.passwordstore.org/
