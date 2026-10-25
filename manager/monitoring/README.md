# Manager monitoring

The example Compose stack publishes Prometheus, Alertmanager, and Grafana on
IPv4 loopback only. Access them locally or through an authenticated tunnel.
Prometheus lifecycle and administrative APIs are disabled. Restart Prometheus
after changing its configuration.

Set `GRAFANA_ADMIN_PASSWORD` to a unique operator secret before starting the
stack with Docker Compose. Compose refuses to start if the value is absent or
empty. Do not commit the secret to this repository. The value initializes a new
Grafana data volume; changing it does not reset an existing volume's password.
For an existing installation that used the old `admin` password, rotate that
account's password through Grafana's account controls. Preserve the data volume.

Set the Manager scrape target in `prometheus.yml` to the address reachable from
the container. The current address is an example, and container loopback is
separate from host loopback. Review the example alert destinations before use.
