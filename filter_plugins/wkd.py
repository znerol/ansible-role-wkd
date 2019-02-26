from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import hashlib
from ansible.module_utils._text import to_bytes, to_text


def _zb32_encode(data):
    """Return data in zbase 32 encoding.

    Data must be convertible to a bytearray.

    Implementation is derived from GnuPG's common/zb32.c
    as published in gnupg-2.1.15.
    """
    zb32asc = "ybndrfg8ejkmcpqxot1uwisza345h769"

    data = bytearray(data)
    databits = len(data) * 8
    datalen = (databits + 7) / 8

    output = ""

    while datalen >= 5:
        output += zb32asc[((data[0]      ) >> 3)                  ]
        output += zb32asc[((data[0] &   7) << 2) | (data[1] >> 6) ]
        output += zb32asc[((data[1] &  63) >> 1)                  ]
        output += zb32asc[((data[1] &   1) << 4) | (data[2] >> 4) ]
        output += zb32asc[((data[2] &  15) << 1) | (data[3] >> 7) ]
        output += zb32asc[((data[3] & 127) >> 2)                  ]
        output += zb32asc[((data[3] &   3) << 3) | (data[4] >> 5) ]
        output += zb32asc[((data[4] &  31)     )                  ]
        data = data[5:]
        datalen -= 5

    if datalen == 4:
        output += zb32asc[((data[0]      ) >> 3)                  ]
        output += zb32asc[((data[0] &   7) << 2) | (data[1] >> 6) ]
        output += zb32asc[((data[1] &  63) >> 1)                  ]
        output += zb32asc[((data[1] &   1) << 4) | (data[2] >> 4) ]
        output += zb32asc[((data[2] &  15) << 1) | (data[3] >> 7) ]
        output += zb32asc[((data[3] & 127) >> 2)                  ]
        output += zb32asc[((data[3] &   3) << 3)                  ]
    elif datalen == 3:
        output += zb32asc[((data[0]      ) >> 3)                  ]
        output += zb32asc[((data[0] &   7) << 2) | (data[1] >> 6) ]
        output += zb32asc[((data[1] &  63) >> 1)                  ]
        output += zb32asc[((data[1] &   1) << 4) | (data[2] >> 4) ]
        output += zb32asc[((data[2] &  15) << 1)                  ]
    elif datalen == 2:
        output += zb32asc[((data[0]      ) >> 3)                  ]
        output += zb32asc[((data[0] &   7) << 2) | (data[1] >> 6) ]
        output += zb32asc[((data[1] &  63) >> 1)                  ]
        output += zb32asc[((data[1] &   1) << 4)                  ]
    elif datalen == 1:
        output += zb32asc[((data[0]      ) >> 3)                  ]
        output += zb32asc[((data[0] &   7) << 2)                  ]

    # Need to strip some bytes if not a multiple of 40.
    output = output[:int((databits + 5 - 1) / 5)]
    return output


def wkd_hash(a, *args, **kw):
    ''' Convert e-mail address to wkd hash '''
    localpart, domain = a.lower().rsplit('@', 1)
    wkdhash = _zb32_encode(hashlib.sha1(to_bytes(localpart)).digest())
    return to_text("{:s}@{:s}".format(wkdhash, domain))


class FilterModule(object):
    ''' Ansible core jinja2 filters '''

    def filters(self):
        return {
            'wkd_hash': wkd_hash,
        }
