# NetFPGA-SBI

This work is aimed at enhancing the P4->NetFPGA project by enabling the implementation of remotely-controllable routing tables.

In order to make use of the contents of this repository, one should first gain access to the P4->NetFPGA github repository and perform the initial setup as described [here](https://github.com/NetFPGA/P4-NetFPGA-public/wiki/Getting-Started).

## Steps for integrating our contribution in the P4->NetFPGA Workflow

1. Create a new P4 project named standalone_switch by running `$ $SUME_SDNET/bin/make_new_p4_proj.py standalone_switch`. This will create a template project in `$SUME_SDNET/projects/`.
2. Update `$SUME_FOLDER/tools/settings.sh` in order to set the `P4_PROJECT_NAME` environment variable to `standalone_switch`.
3. Paste the files `commands.txt`, `SBI_engine.p4` and `standalone_switch.p4` that you will find in `/p4_code` inside `$P4_PROJECT_DIR/standalone_switch/src`, replacing the already existing files. `SBI_engine.p4` contains the definition of the control module responsible for packet routing, while `standalone_switch.p4` is a dummy P4 program that is currently implementing TCP monitor's functionality and can be adapted to other applications.
4. Paste the directory `cam_lut` that you will find in `/extern_function` in `$SUME_SDNET/templates/externs`.
5. Paste the file `bin.patch` present in `/extern_function` in `$SUME_SDNET`, then apply the patch by using `patch -p0 < bin.patch`. This will update `$SUME_SDNET/bin/extern_data.py` by including the path to our new extern function and the related replacements.
6. Paste the files `gen_testdata.py`, and `southbound_headers.py` that you will find in `/testdata` inside `$P4_PROJECT_DIR/standalone_switch/testdata`, replacing the already existing files. `southbound_headers.py` contains the definitions of the packets used in our SBI protocol.
7. Paste `/sw` in `$P4_PROJECT_DIR`. This directory contains the files used to test the physical board after it has been programmed.
