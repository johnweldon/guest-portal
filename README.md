# Guest Portal

This serves as an external portal server for UniFi.

It is very simple and simply presents a Terms and Conditions page which the guest must accept before connecting to the network.

The terms can be overridden by providing an alternative template to the default [`templates/terms.html`](templates/terms.html)

## Development Environment

In bash, set environment with:

    eval $(sed -e 's/^.\{1,\}$/export &/' .env)
