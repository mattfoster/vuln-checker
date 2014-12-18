# vuln-checker

This is a simple Ruby CLI which scrapes security advisory pages and presents information on available fixes in a table.

Here's a text screenshot:

    % ruby -I lib bin/cve
    Showing information for: CVE-2012-3499
    +--------------------+-----------------------------------------------------------+
    | RHEL               | https://access.redhat.com/security/cve/CVE-2012-3499      |
    | RHEL 5             | ✅  (RHSA-2013:0815)                                      |
    | RHEL 6             | ✅  (RHSA-2013:0815)                                      |
    | Debian             | https://security-tracker.debian.org/tracker/CVE-2012-3499 |
    | Debian 6 (squeeze) | ✅                                                        |
    | Debian 7 (wheezy)  | ✅                                                        |
    +--------------------+-----------------------------------------------------------+


Curently only RHEL and Debian pages are supported.

## Dependencies

It requires `terminal-table` and `nokogiri`.