# DRACO

This is an profile for the DRACO verifier for functional verification of eBPF programs. DRACO was presented at the 2nd Workshop on eBPF and Kernel Extension in ACM SIGCOMM 2024. The paper can be found [here](https://dl.acm.org/doi/10.1145/3672197.3673435).

## Working with this repository

Clone it using

```
git clone --recurse-submodules git@github.com:DRACO-verifier/DRACO-verifier.git
```

To set up the environment, run these commands

```
cd DRACO-verifier
./setup-tool.sh
```

This will require sudo access and take a few minutes to complete.

You will need to run the following command at the start of each session if you wish to run DRACO:

```
source path-to-DRACO-verifier/paths.sh
```

## Verifying individual programs

Change the directory to any of the directories in the examples folder, for example the `fw_fullspec` directory, and run these commands:

```
cd path-to-DRACO-verifier/examples/fw_fullspec
make libbpf   # only needs to be run once, or whenever changes to ebpf-se are made
make assert
```

If you wish to load the eBPF program as well, instead of `make assert` run this command:
```
sudo make verify
```

### List of examples for verifying individual programs
* `assert_example`
* `assert_map_example`
* `crab_assert`
* `crab_fullspec`
* `fluvia_assert`
* `fluvia_fullspec`
* `fullspec_example`
* `fw_assert`
* `fw_fullspec`
* `fw_fullspec_reduced`
* `partial_example`
* `partial_example_simple`
* `simple`

## Verifying interactions of eBPF programs

### Analysing interactions between different eBPF programs
Change the directory to one of the directories in the examples folder to verify the interactions between different eBPF programs, for example the `evaluation-two-program-fw-nat` directory, and run the following commands:

```
cd path-to-DRACO-verifier/examples/evaluation-two-program-fw-nat
make libbpf   # only needs to be run once, or whenever changes to ebpf-se are made
make verify-two-phase
```

#### List of example for verifying interactions between different eBPF programs
* `evaluation-two-program-fw-nat`
* `evaluation-two-program-map`
* `evaluation-two-program-no-overlap`

### Analysing interactions between eBPF programs and userspace programs
Change the directory to the `evaluation-branch-on-map` directory, and run the following commands:

```
cd path-to-DRACO-verifier/examples/evaluation-branch-on-map
make libbpf   # only needs to be run once, or whenever changes to ebpf-se are made
make verify-interactions
```

#### List of example for verifying interactions between eBPF programs and userspace programs
* `evaluation-branch-on-map`
