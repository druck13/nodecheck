nodecheck V2
============

Purpose
-------
Check two remote filing system nodes have identical contents.

Installation
------------
Requires Python 3.7 or later on Linux, may run on Windows but untested.

No additional modules are required.


Running
-------
Mount the two filing system nodes on the machine.

    python3 nodecheck.py <first path> <second path>

The paths can either be the mount points of the filing system nodes, or `host:path` in order to use ssh to access
the nodes. SSH keys must be shared to allow this, as password entry is not supported.

The program will run and report if two nodes are different, indential, or appear identical by errors such as
insuffucient permissions prevented the reading of one or more files or directories.

A bash script `nodecheck.sh` has been created to mount the two example nodes and run the python program,
(elevated permissions may be required). Additional command line options (described below) will be passed to the program.

* Node 1: hostname=n1 ipaddr=192.168.0.1/24 share=/mnt/share1/test
* Node 2: hostname=n2 ipaddr=192.168.0.2/24 share=/mnt/share1/test

Additional Options
------------------

`-a (MD5|SHA1|SHA245)`   
Choose the algorithm used for hashing.
* MD5 is the fastest, but has the most risk of collisions.
* SHA1 is the default and is a good compromise between speed and collision risk.
* SHA256 has better collision avoidance, but will result in longer execution times.

`-p`    
Display progress information on the directories being read and the checks performed.

How it works
------------
The program uses two processes to read filing system nodes in parallel, gathering filing system metadata using the
stat command. A hash of the file contents is created using an algorthim
which can be specified on the command line (default SHA1).

If any errors are encountered during the process will be reported.

Once the nodes are read a check is made to ensure that the files exist on both nodes, and which are only found on
one node will be reported. If the set of files are the same, the metadata and hash of the file contemts are checked.

The following metadata is checked
* Mode (UNIX file permissions)
* User id
* Group id
* File size
* Modification time

For the purpose of this example program file access times are not checked to prevent spurious differences,
and the file creation time is not checked to allow testing using normal file creation operations, rather than having to
clone a drive volume.

A drawback of the current implementation is with filing system nodes containing a large
number of files, the two processes gathering the filing system information will return
a large amount of data to the main program, resulting in excessive memory use and poor
performance. See the ToDo section below for possible mitigations.


History
-------
* Version 1
  * Initial release
* Version 2
  * Mountless operation - alternative access the nodes via SSH

ToDo
----
* Unit testing - Implement unit tests
* Robustness   - Investigate further errors which may be encountered when walking the filing systems
* Reduce memory usage - walk both filing system nodes and pass each pair of directories to
a thread pool to read metadata and hashes, and compare.
