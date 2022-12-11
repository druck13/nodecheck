#!/usr/bin/env python3
#
# Python screening exercise
#
#  Node 1: hotsname=n1 ipaddr=192.168.0.1/24
#  Node 2: hotsname=n1 ipaddr=192.168.0.2/24
#  Node 3: hotsname=n1 ipaddr=192.168.0.3/24
#
# Write code that will perform the following when executed on node 3
#    1. Retrieve a list of file objects in /mnt/share1/test on node 1 and node2 in parallel.
#    2. Return success if contents match; error if there is a mismatch.
# Bonus points:
# Include validation of file metadata
# Include data integrity check of files
#
# Notes:
# Could use dircmp, but where would the fun be in that!
#
# The program walks each node in parallel (as instructed) which could result in a lot of data being generated.
# I would walk the filing systems handing off each pair of directories to a thread pool to check the contents.
# This may also extract extra parallelism

import os
import sys
import time
import argparse
import hashlib
from multiprocessing import Pool as ThreadPool


class NodeChecker:
    # constants
    HASHING_ALG = "SHA1"
    STAT_CHECKS = \
    [
        # index, name,              print function
        (0,     "mode",             lambda value: oct(value)[2:]),
       #(1,     "inode",            str),                           # ignore inode
       #(2,     "device",           lambda value: hex(value)[2:]),  # ignore device
       #(3,     "link count",       str),                           # ignore link count
        (4,     "user id",          str),
        (5,     "group id",         str),
        (6,     "size",             str),
       #(7,     "access time",      time.ctime),                    # ignore access time
        (8,     "modified time",    time.ctime),
       #(9,     "creation time",    time.ctime),                    # ignore creation time while testing
    ]

    def __init__(self, algorithm, progress):
        """
        Class to check two filing system nodes have identical contents.

        :param algorithm: algorithm to use for file contents hashing
        :type algorithm: string
        :param progress: display progress
        :type progress: bool
        """
        self.algorithm = algorithm
        self.progress  = progress
        self.files     = {}
        self.errors    = 0

    def get_digest(self, filepath):
        """
        Calculate the hash of a file using the algorithm passed to the class

        :param filepath: path to the file
        :type filepath: string
        :return: has in the form of a hex digest
        :rtype: string
        """
        if self.algorithm == "MD5":
            h = hashlib.md5()
        elif self.algorithm == "SHA1":
            h = hashlib.sha1()
        elif self.algorithm == "SHA256":
            h = hashlib.sha256()
        else:
            raise ValueError("Invalid algorithm %s" % self.algorithm)

        with open(filepath, 'rb') as f:
            while True:
                # Reading is buffered, so we can read smaller chunks.
                chunk = f.read(h.block_size)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest()

    def walk_node(self, node_path):
        """
        Discover all files under the given path and retrieve metadata from os\.stat
        and file hash using the algorithm passed to the class at initialisation.

        :param node_path: path to walk
        :type node_path: string
        :return: tuple of dictionary of file mata and digests keyed on the relative file path, and error count
        :rtype: (dict, int)
        """
        files = {}

        # only interested in the root of the path and the filenames,
        # subsequent iterations will walk the subdirectories
        for dirpath, _, filenames in os.walk(node_path, onerror=self._walk_error):
            if self.progress:
                print("%s" % dirpath)

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    # file key is relative to the path we are given
                    files[os.path.relpath(filepath, node_path)] = \
                        {
                            "metadata" : os.stat(filepath),
                            "digest"   : self.get_digest(filepath),
                        }
                except OSError as e:
                    print(str(e), file=sys.stderr)
                    self.errors += 1

        return files, self.errors

    def _walk_error(self, error):
        print(str(error), file=sys.stderr)
        self.errors += 1

    def check(self, paths):
        """
        Check two filing system paths have identical contents
        :return: True if identical
        :rtype: bool
        """

        # Read file information for each node in parallel
        if self.progress:
            print("Reading directories:")

        with ThreadPool(processes=len(paths)) as pool:
            node_data = pool.map(self.walk_node, paths)

        self.errors = sum(nd[1] for nd in node_data)

        if self.progress:
            print("Checking matching file names")

        # first quick check to ensure all files are present in both nodes
        file_sets = [set(nd[0].keys()) for nd in node_data]
        only_ons  = [file_sets[0] - file_sets[1], file_sets[1] - file_sets[0]]

        for i, only_on in enumerate(only_ons):
            if only_on:
                print("Files only on %s:\n%s" % (paths[i], "\n".join(only_on)))

        # early termination as things obviously different, could have option to continue at this point
        if any(only_ons):
            return False

        # flag to indicate everything matches until we know otherwise
        matching = True

        # second check of metadata and digests
        if self.progress:
            print("Checking file metadata and hashes")

        for filename in node_data[0][0]:
            # should no key errors as we are currently terminating if files don't match, but handle by continuing
            try:
                file0 = node_data[0][0][filename]
                file1 = node_data[1][0][filename]
            except KeyError:
                continue
            meta0 = file0["metadata"]
            meta1 = file1["metadata"]

            # check each item of metadata, except device and inode ids, and link count
            # which don't indicate a difference in contents
            for i, st_name, print_fn in self.STAT_CHECKS:
                if st_name and meta0[i] != meta1[i]:
                    print("%s: %s different: %s != %s" % \
                          (filename, st_name, print_fn(meta0[i]), print_fn(meta1[i])))
                    matching = False

            # check the file has digests are identical
            if file0["digest"] != file1["digest"]:
                print("%s :%s hashes are different" % (filename, self.algorithm))
                matching = False

        return matching


def main():
    parser = argparse.ArgumentParser(description="Check contents of two filing system nodes are identical")
    parser.add_argument("-a", "--algorithm", default=NodeChecker.HASHING_ALG, help="Hash algorithm (MD5, SHA1, SHA256), default %s" % NodeChecker.HASHING_ALG)
    parser.add_argument("-p", "--progress",  action="store_true",             help="Show progress")
    parser.add_argument("path",              nargs=2,                         help="Two paths to check")
    args = parser.parse_args()

    errors = 0
    for path in args.path:
        if not os.path.isdir(path):
            print("'%s' is not a valid path, has it been mounted?" % path, file=sys.stderr)
    if errors:
        sys.exit(1)

    nodechecker = NodeChecker(args.algorithm, args.progress)
    if nodechecker.check(args.path):
        if nodechecker.errors:
            print("Nodes appear to match, but %d errors were encountered" % nodechecker.errors)
        else:
            print("Nodes match")
    else:
        print("Nodes differ", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
