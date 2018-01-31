# arch-signoff

Run `signoff` to get a list of packages you can [sign off][1]. `signoff -i`
lets you interactively sign off packages. See [asciinema][2] for a demo.

To simplify authentication, specify your ArchWeb username and password in the
`ARCHWEB_USERNAME` and `ARCHWEB_PASSWORD` environment variables. For instance,
using [pass][3]:

    alias signoff='ARCHWEB_PASSWORD="$(pass archweb)" signoff'

See LICENSE for license details.

[1]: https://lists.archlinux.org/pipermail/arch-dev-public/2016-July/028191.html
[2]: https://asciinema.org/a/nfTIZNEVcJmP0a8uEfe5MCiej
[3]: https://www.passwordstore.org/
