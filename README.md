# ipls

**ipls** is an iptables pretty-printer, generates easier-to-read output

```
.---------------------------------------------------------------------------------------------.
| INPUT (policy: ACCEPT)                                                                      |
+---+------+------+-------------+------+---------------------+--------+-----------------------+
| # | Int  | Prot | Src         | Dest | State               | Target | Extended              |
+---+------+------+-------------+------+---------------------+--------+-----------------------+
| 1 | eth0 | tcp  |     8.8.8.8 | :22  | NEW                 | REJECT |                       |
+---+------+------+-------------+------+---------------------+--------+-----------------------+
| 2 |      |      |    8.8.8.10 |      |                     | REJECT | reject-with           |
|   |      |      |             |      |                     |        | icmp-port-unreachable |
+---+------+------+-------------+------+---------------------+--------+-----------------------+
| 3 |      | tcp  | 10.10.10.10 | :888 | RELATED,ESTABLISHED | REJECT |                       |
'---+------+------+-------------+------+---------------------+--------+-----------------------'
.--------------------------.
| FORWARD (policy: ACCEPT) |
+--------------------------+
| No rules                 |
'--------------------------'
.-------------------------.
| OUTPUT (policy: ACCEPT) |
+-------------------------+
| No rules                |
'-------------------------'
```

## Usage

### Requires root permissions to dynamically executes iptables

```bash
# ipls [table]
```

### Doesn't require running ipls itself with root permissions

```bash
$ sudo iptables -L -n -v --line-numbers | ipls -
```

This version takes no parameters other than '-' ; if you want to restrict it to a given table, do it with the iptables invocation. 

```bash
$ sudo iptables -L -n -v --line-numbers nat | ipls -
```

## Dependencies

Non-core dependencies are:

- IPTables::Parse
    + Accepting STDIN requires my version here: https://github.com/zedlopez/IPTables-Parse
- first
- one of:
    + Text::Table::Tiny
    + Text::ASCIITable
    + Text::ANSITable
    
Neither Text::ASCIITable nor Text::Table::Tiny have non-core requirements; Text::Table::Tiny is indeed tiny, but Text::ASCIITable's results look better and I doubt one would notice the < 1000 lines of code size difference. Text::ANSITable looks prettier, but pulls in Moo and a lot of dependencies.

