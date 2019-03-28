# Arch Linux Signoff Tool

The `signoff` tool can be used by members of the [Arch Testing Team](https://wiki.archlinux.org/index.php/Arch_Testing_Team) to make it easier
to sign off packags. `signoff -i` lets you interactively sign off packages. See [asciinema](https://asciinema.org/a/nfTIZNEVcJmP0a8uEfe5MCiej) for a demo.

To simplify authentication, specify your ArchWeb username and password in the
`ARCHWEB_USERNAME` and `ARCHWEB_PASSWORD` environment variables. For instance,
using [pass](https://www.passwordstore.org/)

```
alias signoff='ARCHWEB_PASSWORD="$(pass archweb)" signoff'
```

## Dependencies

* pyalpm
* python-click
* python-dateutil
* python-requests
* python-setuptools

## LICENSE

See LICENSE for license details.
