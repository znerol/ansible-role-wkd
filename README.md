Anlibe Role: WKD
================

[![Build Status](https://travis-ci.org/znerol/ansible-role-wkd.svg?branch=master)](https://travis-ci.org/znerol/ansible-role-wkd)

Provides a `wkd_hash()` filter to convert PGP uids into [Web Key Directory][1] hash.

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

License
-------

BSD

[1]: https://wiki.gnupg.org/WKD
