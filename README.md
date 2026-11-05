# Project 3: Subnetting and Forwarding

- Name: Sam Kleman
- Email: spencerkleman@u.boisestate.edu
- Class: 425-001

## Known Bugs or Issues

This router lookup simulation parses the forwarding table using a linear search. This obviously is not a good idea when
the table is 1 million or more entries long. Therefore, if one were to actually use this, they would need to
update table_lookup() in lab.c to use a binary trie.

## Experience

This project was incredibly straightforward, as it asked us to implement the lookup process of a router. This is something we
covered in detail both in class and in the textbook, so it was a simple matter of following the assignment instructions as written.

In terms of design, this program handles the special CIDR boundaries (/0, /31, /32) with explicit conditions. This ensures that
host calculations can be done without undefined behavior in C. /31 uses a point-to-point link, so the first host is the network address
and the last host is the broadcast address. /32 and anything above returns the full mask.

As mentioned above, the forwarding table is parsed using a linear scan to find the longest prefix. Specifically, the function checks
every route to see if they contain the destination and, if so, saves the route with the longest prefix.