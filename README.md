Anlibe Role: WKD
================

[![Build Status](https://travis-ci.org/znerol/ansible-role-wkd.svg?branch=master)](https://travis-ci.org/znerol/ansible-role-wkd)

Provides Jinja2 filter plugins to hash PGP user ids in the form required by the
[Web Key Directory][1] [draft standard][2].

* `wkd_hash()`: Returns the WKD hash given a PGP user id string.
* `wkd_host(wkd_method=["advanced","direct"])`: Returns the domain-part derived
  from given PGP user id string. If `wkd_method` is set to `advanced` the
  `openpgpkey` sub-domain is prepended (see section *Key Discovery* in
  [draft standard][2]).
* `wkd_dir(wkd_method=["advanced","direct"])`: Returns the directory path
  derived from the given PGP user id string (see section *Key Discovery* in
  [draft standard][2]).
* `wkd_url(wkd_method=["advanced","direct"])`: Returns the WKD URL derived from
  the given PGP user id string (see section *Key Discovery* in
  [draft standard][2]).


Note that this role essentially contains pure Python implementation of the WKD
hash algorithm. It does not depend on GnuPG command line/library, nor does it
provide modules / tasks capable of manipulating PGP key files. The following
projects/roles provide higher level abstractions:

* [znerol.wkd\_gpg](https://galaxy.ansible.com/znerol/wkd_gpg): Export GPG keys
  into a WKD directory structure.

Requirements
------------

None

Role Variables
--------------

None

Dependencies
------------

None

Example Playbook
----------------

Usage of `wkd_hash` filter:

    - hosts: localhost
      tasks:
        - import_role:
            name: znerol.wkd

        - loop:
            - "Joe.Doe@Example.ORG"
            - "joe.doe@Example.com"
            - "test-wkd@example.org"
            - "me@example.com"
            - "äëöüï@example.org"
            - "foo@example.com"
          debug:
            msg: "WKD hash for {{ item }} is {{ item | wkd_hash() }}"

See [test/test.yml](tests/test.yml) for sample input/output.

License
-------

GPLv3

[1]: https://wiki.gnupg.org/WKD
[2]: https://tools.ietf.org/html/draft-koch-openpgp-webkey-service
