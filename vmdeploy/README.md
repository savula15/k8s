# [Virtualization] SDK.

## Introduction

[Virtualization] is the sdk that provides an interface to deploy CN-NOS VM's. 
Its gateway to the CN-NOS virtualization !!

The supported APIs are list below.

- [x] Supported APIs
  - [x] [Deploy]
  - [x] [Teardown]
  - [x] [Monolithic]
  - [x] [Non-Monolithic]
  - [x] [CustomSnapl]
  - [x] [ReloadCharts]


## Installation

```
pip install virtualization
```

## Usage

```
from virtualization import Virtualization

cluster = "dev-cluster1"
user = "savula"

vm = virtualization.Virtualization(cluster, user)

topology = "demo"
topology_type = "node"
monolithic = True

deployed, vms = vm.deploy(topology=topology, topology_type=topology_type, monolithic=monolithic)

print(deployed, vms)
```


