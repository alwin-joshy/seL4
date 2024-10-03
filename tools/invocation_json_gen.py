#!/usr/bin/env python3
#
# Copyright 2024, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause or GPL-2.0-only
#

import argparse
import json

def parse_args():
	parser = argparse.ArgumentParser(description='Generate JSON file containing list of seL4 \
									invocations')
	parser.add_argument('--invocation', type=argparse.FileType('r'))
	parser.add_argument('--arch_invocation', type=argparse.FileType('r'))
	parser.add_argument('--sel4_arch_invocation', type=argparse.FileType('r'))
	parser.add_argument('--dest', type=argparse.FileType('w+'))

	return parser.parse_args()


if __name__ == "__main__":
	args = parse_args()

	invocations = json.load(args.invocation)
	sel4_arch_invocations = json.load(args.sel4_arch_invocation)
	arch_invocations = json.load(args.arch_invocation)

	res = {}
	for i, val in enumerate(invocations + sel4_arch_invocations + arch_invocations):
		res[val] = i + 1

	json.dump(res, args.dest)