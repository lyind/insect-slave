# insect-slave
Minimal service discovery slave implementation implemented in C

## Dependencies
* Unix like operating system
* C compiler

## Help

```
insect-slave.c - Simple insect slave implementation

USAGE:

  insect-slave [OPTIONS] COMMAND

COMMANDS:

  keep-alive        Send periodic mapping messages, shutdown on demand
  lookup            Lookup dependency

OPTIONS:

  -h                  Show this help

  -d DEPENDENCY_ROUTE Slave dependency route (up to 16 allowed)
  -p SLAVE_PORT       Slave port
  -P QUEEN_PORT       Remote queen port
  -q QUEEN_HOST       Remote queen hostname or address
  -r ROUTE            Slave route
  -s SLAVE_HOST       Slave host address or name
```

