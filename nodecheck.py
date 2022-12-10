#!/usr/bin/env python3
#
# Hitachi Ventura Python screening exercise
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
# The program walks each node in parallel as instructed which could result in a lot of data being generated.
# I would walk the filing systems handing off each pair of directories to a thread pool to check the contents
# This may also extract extra parallelism

import os
import sys
import argparse
import hashlib
from multiprocessing import Pool as ThreadPool


HASHING_ALG = "SHA1"


class NodeChecker:
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

    def get_digest(self, filepath):
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
        :return: dictionary of file mata and digests, keyed on the relative file path
        :rtype: dict
        """
        files = {}

        # only interested in the root of the path and the filenames,
        # subsequent iterations will walk the subdirectories
        for dirpath, _, filenames in os.walk(node_path):
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
                    sys.stderr.write("Error reading %r: %s" % (filepath, str(e)))

        return files

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
            files_list = pool.map(self.walk_node, paths)

        if self.progress:
            print("Checking matching file names")

        # first quick check to ensure all files are present in both nodes
        file_sets = [set(files.keys()) for files in files_list]
        only_ons  = [file_sets[0] - file_sets[1], file_sets[1] - file_sets[0]]

        for i, only_on in enumerate(only_ons):
            if only_on:
                print("Files only on %s:- %s\n" % (paths[i], "\n".join(only_on)))

        # early termination as things obviously different, could have option to continue at this point
        if any(only_ons):
            return False

        # flag to indicate everything matachs until we know otherwise
        matching = True

        # second check of metadata and digests
        if self.progress:
            print("Checking file metadata and hashes")

        for filename in files_list[0]:
            # should no key errors as we are currently terminating if files don't match, but handle by continuing
            try:
                file0 = files_list[0][filename]
                file1 = files_list[1][filename]
            except KeyError:
                continue
            meta0 = file0["metadata"]
            meta1 = file1["metadata"]

            # check each item of metadata, except device and inode ids, and link count
            # which don't indicate a difference in contents
            for i, st_name in enumerate(["mode", None, None, None, "uid", "gid", "size", "atime", "mtime", "ctime"]):
                if st_name and meta0[i] != meta1[i]:
                    print("%r metadata different, %s: %s != %s" % (filename, st_name, meta0[i], meta1[i]))
                    matching = False

            # check the file has digests are identical
            if file0["digest"] != file1["digest"]:
                print("%r %s hashes are different" % (filename, self.algorithm))
                matching = False

        return matching


def main():
    parser = argparse.ArgumentParser(description="Check contents of two filing system nodes are identical")
    parser.add_argument("-a", "--algorithm", default=HASHING_ALG, help="Hash algorithm (MD5, SHA1, SHA256), default %s" % HASHING_ALG)
    parser.add_argument("-p", "--progress",  action="store_true", help="Show progress")
    parser.add_argument("paths",             nargs=2,             help="Paths to examine")
    args = parser.parse_args()

    errors = 0
    for path in args.paths:
        if not os.path.isdir(path):
            sys.stderr.write("'%s' is not a valid path, has it been mounted?" % path)
    if errors:
        sys.exit(1)

    nodechecker = NodeChecker(args.algorithm, args.progress)
    if not nodechecker.check(args.paths):
        sys.stderr.write("Nodes differ")
        sys.exit(2)


if __name__ == "__main__":
    main()
