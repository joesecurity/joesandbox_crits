# Joe Sandbox CRITs

The Joe Sandbox CRITs service allows you to access the full power of Joe Sandbox
from inside [CRITs](https://crits.github.io/).

![CRITs sends sample to Joe Sandbox which re-inserts ips, domains, screenshots, dropped files and the full report.](img/flow.png)

The service automatically extracts many IOCs from the sample and inserts them
automatically into CRITs enabling analysts to understand the connection between
multiple samples.

## Installation

A more general description is available on the [CRITs github page][guide-adding-services].

This guide assumes you installed the [CRITs services repository] in `/data/crits_services`.

1. Clone this repository into `/data/crits_services/joesandbox_crits`
2. Run `cd /data/crits_services && ./bootstrap` to install all dependencies.
3. Configure the service in the CRITs web interface.

![Joe Sandbox service button](img/service.png)


 [guide-adding-services]: https://github.com/crits/crits/wiki/Adding-services-to-CRITs
