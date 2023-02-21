# Workshop (Osquery)

Welcome to the workshop.



|  |  | **Please ensure you have prepared your machine well in advance of the workshop. Your time during the workshop is valuable, and we want to use it for learning, rather than setting up machines.** | | |
| ---- | :----------------------------------------------------------: | :--: | :--: | ---- |

## Index

*NOTE* : *If you have any difficulty preparing your machine, or following this document, please raise an issue in this repository ASAP so that we can resolve the problem before the workshop begins.*

- [Workshop (Osquery)](#workshop-osquery)
  - [Index](#index)
  - [Introduction to Osquery](#introduction-to-osquery)
  - [Prerequisites](#prerequisites)
  - [Run Osquery](#run-osquery)
  - [Basic Commands](#basic-commands)
  - [Osqueryi](#osqueryi)
  - [Osqueryd](#osqueryd)
  - [Your first query](#your-first-query)
  - [Demo](#demo)
  - [FAQ](#faq)
      - [Error while executing Osquery?](#error-while-executing-osquery)
      - [What is osqueryd and osqueryi?](#what-is-osqueryd-and-osqueryi)
      - [Mode of execution for osqeryd and osqueryi?](#mode-of-execution-for-osqeryd-and-osqueryi)

## Introduction to Osquery

- Osquery is an operating system instrumentation framework for Windows, OS X (macOS), and Linux.
- Osquery exposes an operating system as a high-performance relational database.
- Osquery exposes an operating system as a high-performance relational database. 
- This allows you to write SQL queries to explore operating system data. 
- With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.
- The daemon takes care of aggregating the query results over time and generates logs which indicate state changes in your infrastructure. 
- The interactive query console, osqueryi, gives you a SQL interface to try out new queries and explore your operating system. 
- Even though osquery takes advantage of very low-level operating system APIs, you can build and use osquery on Windows, macOS, Ubuntu, CentOS and other popular enterprise Linux distributions. 
- This has the distinct advantage of allowing you to be able to use one platform for monitoring complex operating system state across your entire infrastructure.
- Monitor your corporate Windows or macOS clients the same way you monitor your production Linux servers.
- Osqueryi is the osquery interactive query console/shell. In this mode, it is completely standalone, does not communicate with a daemon, and does not need to run as an administrator (although some tables may return fewer results when running as non-administrator).
- The shell does not keep much state, or connect to the osqueryd daemon
- osqueryd is the host monitoring daemon that allows you to schedule queries and record OS state changes. The daemon aggregates query results over time and generates logs, which indicate state change according to each query. The daemon also uses OS eventing APIs to record monitored file and directory changes, hardware events, network events, and more.

## Prerequisites

- Linux (Any Distro)
- [Docker](https://docs.docker.com/engine/install/)
- [Osquery](https://osquery.io/downloads/official/5.7.0)  
  <sup>Official Build</sup>
- [Osquery](https://drive.google.com/drive/folders/1kV8moPmKZDxnoHKJCwVHcVmI-6uYYeW9?usp=sharing)  
  <sup>Our Custom Build</sup>
- Optional: [VsCode](https://code.visualstudio.com/) ([download](https://code.visualstudio.com/Download))


## Run Osquery

```bash
  sudo ./osqueryd -S --disable_events=false --enable_bpf_events=true --enable_bpf_file_events=true --config_path /etc/osquery/fim.conf
```

## Basic Commands
```bash
    .help
    .all [TABLE] - Select all from a table
    .tables - List all tables
    .schema [TABLE]- List schema of all tables (supported)
    .schema --enable_foreign - To see schema in your shell for tables foreign to your OS
    .mode [column | csv | line | list | pretty]

```

## Osqueryi
```bash
    osqueryi --json "SELECT * FROM routes WHERE destination = '::1'"]
    echo "SELECT * FROM listening_ports where port > 8000;" | osqueryd -S --json
    to list all tables: .tables
    to list the schema (columns, types) of a specific table: .schema table_name or pragma table_info(table_name); for more details
    to list all available commands: .help
    to exit the console: .exit or ^D
```

## Osqueryd
```javascript
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "hardware_events": {
      "query": "SELECT * FROM hardware_events;",
      "interval": 10
    }
  }
}
```

## Your first query
```sql
SELECT pid, name, path FROM processes LIMIT 1;
```

## Demo

- ### [Text4Shell](/Attack/text4shell-poc/README.md)
- ### [Apt-spawn-shell](/Attack/Apt-spawn-shell/README.MD)
- ### [Docker-attacks](/Attack/Docker-attacks/README.MD)
- ### [Key-Logger](https://github.com/gsingh93/simple-key-logger)



## FAQ

#### Error while executing Osquery?

Please check your Build and Architecture of your host system 

#### What is osqueryd and osqueryi?

osqueryd is the demon version of Osquery and osqueryi is the interactive shell version.

#### Mode of execution for osqeryd and osqueryi?

When you run osqueryd the logs are collected in /var/log/osquery and when you run osqueryi it will not log anything it will just give you the interactive shell.



<!-- **NOTE**: If you open a database, open it as *'shared'* as otherwise LiteDb Studio will lock the database and your exercises won't work anymore. -->
